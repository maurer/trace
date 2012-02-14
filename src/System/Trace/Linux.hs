module System.Trace.Linux 
(Regs(..)
,PTRegs(..)
,Event(..)
,Trace
,TraceHandle
,TracePtr(..)
,setBreak
,tracePlusPtr
,runTrace
,traceIO
,traceExec
,traceEvent
,detach
,getRegs
,setRegs
,traceWithHandler
,nopSyscall
,readByteString
,writeByteString
,getData
,setData
,tracePeek
,tracePoke
,traceReadNullTerm
,traceWriteNullTerm
,rawTracePtr
,PPid(..)
,TPid(..)
,contextSwitch
,stepCurrent
,sleep
,wakeUp
) where

import System.Posix.Signals
import System.Exit
import System.PTrace
import Control.Monad.Reader
import Foreign.Storable
import Foreign.Ptr
import Data.Binary
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
import Foreign.Marshal.Alloc
import Foreign.C.Types
import System.Mem.Weak
import qualified Data.Map as Map
import Data.IORef

type TPid = PPid

instance Show TPid where
  show (P x) = show x

debug = \_ -> return () --liftIO . putStrLn
type Regs = PTRegs

nopRegs :: Regs -> Regs
nopRegs r = r {orig_rax = 39} --TODO fetch from a header file

assertMsg :: String -> Bool -> Trace ()
assertMsg _ True  = return ()
assertMsg m False = error m

data ThreadHandle = T {th :: PTraceHandle, breaks :: IORef (Map.Map WordPtr Word8), sysState :: IORef Bool, awake :: IORef Bool, running :: IORef Bool}

data TraceHandle = TH {cur :: IORef PPid, thThreads :: IORef (Map.Map PPid ThreadHandle), delay :: IORef [(PPid, StopReason)]}

writeI x y = liftIO $ writeIORef x y
readI x = liftIO $ readIORef x

currentHandle :: Trace ThreadHandle
currentHandle = do
   l <- ask
   p <- readI (cur l)
   pidHandle p

pidHandle :: PPid -> Trace ThreadHandle
pidHandle p = do
  d <- fmap thThreads ask
  fmap (Map.! p) $ readI d

--TODO make sure Int is the right type for signal and exit
data Event = PreSyscall | PostSyscall | Signal Signal | Exit ExitCode | Breakpoint | Split TPid deriving (Eq, Show)

newtype TracePtr a = TP (PTracePtr a)

rawTracePtr :: Ptr a -> TracePtr a
rawTracePtr = TP . PTP

tracePlusPtr :: TracePtr a -> Int -> TracePtr a
tracePlusPtr (TP ptp) n = TP $ pTracePlusPtr ptp n

type Trace a = ReaderT TraceHandle IO a
type Size = Int -- Used by sizeOf, so probably OK
runTrace :: TraceHandle -> Trace a -> IO a
runTrace h m = do
  runReaderT m h

setBreak :: TracePtr Word8 -> Trace ()
setBreak tp@(TP (PTP p)) = do
  mbreaks <- fmap breaks currentHandle
  bdb <- readI mbreaks
  orig <- tracePeek tp
  tracePoke tp $ 0xcc
  writeI mbreaks (Map.insert (ptrToWordPtr p) orig bdb)

buildT :: PTraceHandle -> Bool -> IO ThreadHandle
buildT pth z = do
  f <- newIORef z
  b <- newIORef $ Map.empty
  c <- newIORef True
  r <- newIORef False
  return $ T pth b f c r

buildTH :: PTraceHandle -> IO TraceHandle
buildTH pth = do
  cur0 <- buildT pth False
  cur <- newIORef (getPPid pth)
  ts  <- newIORef $ Map.fromList [(getPPid pth, cur0)]
  d   <- newIORef []
  return $ TH cur ts d

-- | Trace an IO action
traceIO :: IO ()
        -> IO TraceHandle
traceIO m = buildTH =<< (forkPT m)

-- | Trace an application
traceExec :: FilePath -> [String] -> IO TraceHandle
traceExec file args = buildTH =<< (execPT file False args Nothing)

-- | Continue execution until an event from the list is hit
traceEvent :: (TPid -> Event -> Bool) -> Trace (TPid, Event)
traceEvent predicate = do
  stepCurrent -- Unpause the current task so we know at least _something_
              -- is incoming
  (tp, event) <- procEvent
  if predicate tp event
    then return (tp, event)
    else traceEvent predicate

stepCurrent :: Trace ()
stepCurrent = do
  z <- fmap awake currentHandle
  z' <- liftIO $ readIORef z
  y <- fmap running currentHandle
  y' <- liftIO $ readIORef y
  if z' && (not y')
    then do writeI y True
            liftPT advance
    else return ()

sleep :: Trace ()
sleep = do
  z <- fmap awake currentHandle
  liftIO $ writeIORef z False
--TODO make this less "special"
wakeUp :: TPid -> Trace ()
wakeUp tpid = do
  th <- ask
  z <- fmap (awake . (Map.! tpid)) $ readI $ thThreads th
  z' <- readI z
  if z'
     then return ()
     else do contextSwitch tpid
             liftIO $ writeIORef z True

notRunning tpid = do
  th <- ask
  z <- fmap (running . (Map.! tpid)) $ readI $ thThreads th
  writeI z False

-- Internal, don't export
liftPT :: PTrace a -> Trace a
liftPT m = do
  pt <- fmap th currentHandle
--TODO handle error nicely
  k <- liftIO $ runPTrace pt m
  case k of
    Left e -> error (show e)
    Right r -> return r

bufNextEvent = do
  d <- fmap delay ask
  p <- fmap cur ask
  p' <- readI p
  xs <- readI d
  (pid, ev0) <- case xs of
                  x : xs' -> do writeI d xs'
                                return x
                  [] -> liftIO $ nextEvent p'
  t <- fmap thThreads ask
  t' <- readI t
  case Map.lookup pid t' of
    Just _  -> return (pid, ev0)
    Nothing -> do z <- bufNextEvent
                  xs' <- readI d
                  writeI d ((pid, ev0) : xs')
                  return z

procEvent :: Trace (TPid, Event)
procEvent = do
  (pid, ev0) <- bufNextEvent
  contextSwitch pid
  notRunning pid
  ev <- eventTranslate ev0
  case ev of
    Breakpoint -> do
      mbreaks <- fmap breaks currentHandle
      bdb <- readI mbreaks
      r <- getRegs
      let pc = (rip r) - 1
      let pcp = fromIntegral pc
      tracePoke (rawTracePtr $ wordPtrToPtr $ pcp) (bdb Map.! pcp)
      r <- getRegs
      setRegs $ r {rip = pc}
      writeI mbreaks bdb
      -- TODO do we want behavior like a normal debugger where we put the breakpoint back later?
    _ -> return ()
  return (pid, ev)

contextSwitch :: TPid -> Trace ()
contextSwitch pid@(P p) = do
  th <- ask
  writeI (cur th) pid

eventTranslate :: StopReason -> Trace Event
eventTranslate SyscallState = do
  b <- fmap sysState currentHandle
  c <- readI b
  writeI b (not c)
  if c
    then return PostSyscall
    else return PreSyscall
eventTranslate (ProgExit c) = return $ Exit c
eventTranslate (Sig 5)      = return $ Breakpoint
eventTranslate (Sig 11)     = return $ error "SIGSEGV"
eventTranslate (Sig n)      = return $ Signal n
eventTranslate (Forked pt)  = do
  n <- ask
  ts <- readI $ thThreads n
  th <- liftIO $ buildT pt False
  tdb <- readI $ thThreads n
  writeI (thThreads n) (Map.insert (getPPid pt) th tdb)
  return $ Split $ getPPid pt

-- | Detach from the program and let it proceed untraced
--   This invalidates the trace handle, and any actions after
--   this using it risk triggering an error.
detach :: Trace ()
detach = liftPT detachPT

-- | Get the register structure. As Regs is arch dependent, be careful.
getRegs :: Trace Regs
getRegs = liftPT getRegsPT

-- | Sets the register structure. As Regs is arch dependent, be careful.
setRegs :: Regs -> Trace ()
setRegs regs = liftPT $ setRegsPT regs

-- | Takes some event handlers and continues the trace with them.
--   Exact behavior is still in the air concerning early termination.
traceWithHandler :: (TPid -> Event -> Trace ()) -> Trace ()
traceWithHandler handler = do
  stepCurrent
  (pid, event) <- procEvent
  handler pid event
  case event of
    Exit _ -> do n <- ask 
                 m <- readI (thThreads n)
--TODO accelerate
                 case Map.toList (Map.delete pid m) of
                   [] -> return ()
                   (pid', _) : _ -> do contextSwitch pid'
                                       writeI (thThreads n) (Map.delete pid m)
                                       traceWithHandler handler
    _      -> traceWithHandler handler

-- | Sets the registers up to make a no-op syscall
nopSyscall :: Trace ()
nopSyscall = do
  r <- getRegs
  setRegs $ nopRegs r

readByteString :: TracePtr CChar -> Size -> Trace ByteString
readByteString src size = do
  debug "ReadBS Enter"
  target <- liftIO $ mallocBytes size
  size' <- getData target src size
  -- assertMsg "tried to read a bytestring from unmapped memory" (size == size')
  debug "ReadBS Exit"
  packed <- liftIO $ BS.packCStringLen (target, size)
  liftIO $ free target
  return packed

writeByteString :: ByteString -> TracePtr CChar -> Trace ()
writeByteString bs target = do
  th <- ask
  liftIO $ unsafeUseAsCString bs $ \cs -> runTrace th $
    setData target cs (BS.length bs)

getData :: Ptr a -> TracePtr a -> Size -> Trace Size
getData target (TP src) size = liftPT $ getDataPT target src size

setData :: TracePtr a -> Ptr a -> Size -> Trace ()
setData (TP target) src size = liftPT $ setDataPT target src size

tracePeek :: forall a. (Storable a) => TracePtr a -> Trace a
tracePeek src = do
  let size = sizeOf (undefined :: a)
  target <- liftIO $ mallocBytes size
  getData target src size
  res <- liftIO $ peek target
  liftIO $ addFinalizer res (free target)
  return res

tracePoke :: forall a. (Storable a) => TracePtr a -> a -> Trace ()
tracePoke target v = do
  let size = sizeOf (undefined :: a)
  th <- ask
  liftIO $ allocaBytes size $ \src -> do
    poke src v
    runTrace th $ setData target src size

traceReadNullTerm :: TracePtr CChar -> Size -> Trace ByteString
traceReadNullTerm raw sz = do
  th <- ask
  debug "traceReadNullTerm"
  liftIO $ allocaBytes sz $ \buf -> runTrace th $ do
    size <- getData buf raw sz
    term <- liftIO $ fmap or $ mapBuf (== 0) (buf, size)
    if term
      then liftIO $ BS.packCString buf
      else liftIO $ BS.packCStringLen (buf, size - 1)
  where mapBuf :: (CChar -> a) -> (Ptr CChar, Int) -> IO [a]
        mapBuf f (buf, size) = liftIO $
          mapM (\i -> fmap f $ peek (buf `plusPtr` i)) [0..size - 1]

traceWriteNullTerm :: ByteString -> TracePtr CChar -> Trace ()
traceWriteNullTerm bs ptr = writeByteString (BS.snoc bs 0) ptr
