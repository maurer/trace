module System.Trace.Linux 
(Regs(..)
,PTRegs(..)
,Event(..)
,TraceHandle
,TracePtr
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
) where

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


type Regs = PTRegs

nopRegs :: Regs -> Regs
nopRegs r = r {orig_rax = 39} --TODO fetch from a header file

assertMsg :: String -> Bool -> Trace ()
assertMsg _ True  = return ()
assertMsg m False = error m

newtype TraceHandle = TH PTraceHandle

--TODO make sure Int is the right type for signal and exit
data Event = PreSyscall | PostSyscall | Signal Int | Exit Int

newtype TracePtr a = TP (PTracePtr a)

tracePlusPtr :: TracePtr a -> Int -> TracePtr a
tracePlusPtr (TP ptp) n = TP $ pTracePlusPtr ptp n

type Trace a = ReaderT TraceHandle IO a
type Size = Int -- Used by sizeOf, so probably OK
runTrace :: TraceHandle -> Trace a -> IO a
runTrace h m = runReaderT m h

-- | Trace an IO action
traceIO :: IO ()
        -> IO TraceHandle
traceIO = (fmap TH) . forkPT

-- | Trace an application
traceExec :: FilePath -> [String] -> IO TraceHandle
traceExec file args = fmap TH $ execPT file False args Nothing

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
  TH pth <- ask
  liftIO $ runPTrace pth m

advanceEvent :: Trace Event
advanceEvent = fmap eventTranslate $ liftPT continue
  where eventTranslate :: StopReason -> Event
        eventTranslate SyscallEntry = PreSyscall
        eventTranslate SyscallExit  = PostSyscall

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
  traceWithHandler handler

-- | Sets the registers up to make a no-op syscall
nopSyscall :: Trace ()
nopSyscall = do
  r <- getRegs
  setRegs $ nopRegs r

readByteString :: TracePtr CChar -> Size -> Trace ByteString
readByteString src size = do
  target <- liftIO $ mallocBytes size
  size' <- getData target src size
  assertMsg "tried to read a bytestring from unmapped memory" (size == size')
  liftIO $ unsafePackMallocCString target

writeByteString :: ByteString -> TracePtr CChar -> Trace ()
writeByteString bs target = do
  th <- ask
  liftIO $ unsafeUseAsCString bs $ \cs -> runTrace th $ do
    size <- setData target cs (BS.length bs)
    assertMsg "tried to write a bytestring on unmapped memory" $
      size == (BS.length bs)

getData :: Ptr a -> TracePtr a -> Size -> Trace Size
getData target (TP src) size = liftPT $ getDataPT target src size

setData :: TracePtr a -> Ptr a -> Size -> Trace Size
setData (TP target) src size = liftPT $ setDataPT target src size

tracePeek :: forall a. (Storable a) => TracePtr a -> Trace a
tracePeek src = do
  let size = sizeOf (undefined :: a)
  target <- liftIO $ mallocBytes size
  size' <- getData target src size
  assertMsg "peeked at unmapped memory" (size == size')
  res <- liftIO $ peek target
  liftIO $ addFinalizer res (free target)
  return res

tracePoke :: forall a. (Storable a) => TracePtr a -> a -> Trace ()
tracePoke target v = do
  let size = sizeOf (undefined :: a)
  th <- ask
  liftIO $ allocaBytes size $ \src -> do
    poke src v
    runTrace th $ do size' <- setData target src size
                     assertMsg "poked at unmapped memory" (size == size')

traceReadNullTerm :: TracePtr CChar -> Trace ByteString
traceReadNullTerm raw = do
  th <- ask
  liftIO $ allocaBytes bufSize $ \buf -> runTrace th $ do
    size <- getData buf raw bufSize
    assertMsg "reached unmapped memory while looking for a zero" (size /= 0)
    term <- liftIO $ fmap or $ mapBuf (== 0) (buf, size)
    if term
      then liftIO $ BS.packCString buf
      else do bs  <- liftIO $ BS.packCStringLen (buf, size)
              bs' <- traceReadNullTerm $ raw `tracePlusPtr` size
              return $ BS.append bs bs'
  where bufSize = 4096
        mapBuf :: (CChar -> a) -> (Ptr CChar, Int) -> IO [a]
        mapBuf f (buf, size) = liftIO $
          mapM (\i -> fmap f $ peek (buf `plusPtr` i)) [0..size - 1]

traceWriteNullTerm :: ByteString -> TracePtr CChar -> Trace ()
traceWriteNullTerm bs ptr = writeByteString (BS.snoc bs 0) ptr
