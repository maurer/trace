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
,advanceEvent
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
import Control.Concurrent.MVar

debug = \_ -> return () --liftIO . putStrLn
type Regs = PTRegs

nopRegs :: Regs -> Regs
nopRegs r = r {orig_rax = 39} --TODO fetch from a header file

assertMsg :: String -> Bool -> Trace ()
assertMsg _ True  = return ()
assertMsg m False = error m

data TraceHandle = TH {pth :: PTraceHandle, breaks :: MVar (Map.Map WordPtr Word8)}

tTakeMVar x = liftIO $ takeMVar x
tPutMVar x y = liftIO $ putMVar x y

--TODO make sure Int is the right type for signal and exit
data Event = PreSyscall | PostSyscall | Signal Signal | Exit ExitCode | Breakpoint deriving (Show, Eq)

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
setBreak tp@(TP (PTP p))= do
  mbreaks <- fmap breaks ask
  bdb <- tTakeMVar mbreaks
  orig <- tracePeek tp
  tracePoke tp $ 0xcc
  tPutMVar mbreaks (Map.insert (ptrToWordPtr p) orig bdb)

-- | Trace an IO action
traceIO :: IO ()
        -> IO TraceHandle
traceIO m = do
  -- TODO refactor this to have a THbuilder
  mv <- newMVar Map.empty
  (fmap (\x -> TH x mv)) $ forkPT m

-- | Trace an application
traceExec :: FilePath -> [String] -> IO TraceHandle
traceExec file args = do
  mv <- newMVar Map.empty
  fmap (\x -> TH x mv) $ execPT file False args Nothing

-- | Continue execution until an event from the list is hit
traceEvent :: (Event -> Bool) -> Trace ()
traceEvent predicate = do
  event <- advanceEvent
  if predicate event
    then return ()
    else traceEvent predicate

-- Internal, don't export
liftPT :: PTrace a -> Trace a
liftPT m = do
  pt <- fmap pth ask
--TODO handle error nicely
  Right r <- liftIO $ runPTrace pt m
  return r

advanceEvent :: Trace Event
advanceEvent = do
  ev <- fmap eventTranslate $ liftPT continue
  case ev of
    Breakpoint -> do
      mbreaks <- fmap breaks ask
      bdb <- tTakeMVar mbreaks
      r <- getRegs
      let pc = (rip r) - 1
      let pcp = fromIntegral pc
      tracePoke (rawTracePtr $ wordPtrToPtr $ pcp) (bdb Map.! pcp)
      r <- getRegs
      setRegs $ r {rip = pc}
      tPutMVar mbreaks bdb
      -- TODO do we want behavior like a normal debugger where we put the breakpoint back later?
    _ -> return ()
  return ev
  where eventTranslate :: StopReason -> Event
        eventTranslate SyscallEntry = PreSyscall
        eventTranslate SyscallExit  = PostSyscall
        eventTranslate (ProgExit c) = Exit c
        eventTranslate (Sig 5)      = Breakpoint
        eventTranslate (Sig n)      = Signal n

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
traceWithHandler :: (Event -> Trace ()) -> Trace ()
traceWithHandler handler = do
  event <- advanceEvent
  handler event
  case event of
    Exit _ -> return ()
    _        -> traceWithHandler handler

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
