{-# LANGUAGE LambdaCase #-}

module Main (main) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import           Data.ByteString (ByteString)

import           Text.Parsec

import           Control.Monad.Identity
import           System.Process
import           Data.Maybe
import           Data.Either
import           Data.Ord
import           Data.List (sortBy)
import           GHC.IO.Handle
import           System.IO
import           Numeric

-- C preprocessor
cpp, echo :: String
cpp = "cpp"
echo = "echo"

unistdRelative = C.pack "asm/unistd_64.h"

-- sys/syscall.h should include the real syscall table
dummyC :: String
dummyC = "include <sys/syscall.h>"

extractUnistd64 = fmap extract . listToMaybe . filter (\x -> unistdRelative `C.isInfixOf` x) . C.lines
  where
    extract line = (C.unpack . C.init . C.tail) p
      where (_:_:p:_) = C.words line

getUnistd :: IO (Maybe FilePath)
getUnistd = do
  let echoCommand = (proc echo ["#include <sys/syscall.h>"]) { std_out = CreatePipe }
  withCreateProcess echoCommand $ \_ (Just echoOut) _ echoHand -> do
    withCreateProcess ((shell cpp) { std_in = UseHandle echoOut, std_out = CreatePipe }) $ \_ (Just cpph) _ cppHand -> do
      return . extractUnistd64 =<< (S.hGetContents cpph)

type SyscallEntryDesc = (Int, String)

readDec' :: String -> Int
readDec' = maybe 0 fst . listToMaybe . readDec

defineSyscall :: Monad m => ParsecT ByteString u m (Int, String)
defineSyscall = do
  string "#define"
  many1 space
  string "__NR_"
  syscallName <- many1 (noneOf " ")
  many1 space
  syscallNum_  <- many1 digit
  spaces
  case readDec syscallNum_ of
    ((syscallNum, _):_) -> return $! (syscallNum, syscallName)
    _                   -> parserFail $ "defineSyscall: no parse for syscall number: " ++ syscallNum_

parseSyscallEntries = snd . partitionEithers . map (\line -> runIdentity . runParserT defineSyscall 0 (C.unpack line) $ line) . C.lines

readSyscallTable :: FilePath -> IO [SyscallEntryDesc]
readSyscallTable fp = S.readFile fp >>= return . parseSyscallEntries

genSyscallTable :: IO [SyscallEntryDesc]
genSyscallTable = do
  unistd <- getUnistd
  case unistd of
    Nothing -> return []
    Just fp -> sortBy (comparing fst) <$> readSyscallTable fp

genSCs = genSyscallTable >>= \case
    [] -> return ()
    (s:ss) -> do
      putStrLn              $ "data SysCall = SC" ++ snd s
      mapM_ (\s -> putStrLn $ "             | SC" ++ snd s) ss
      putStrLn              $ "             deriving (Show, Eq, Ord, Bounded)"

genSCTable = genSyscallTable >>= \case
  [] -> return ()
  (s:ss) -> do
    putStrLn                $ "syscallMap = Map.fromList [ (SC" ++ snd s ++ ", #const SCMP_SYS(" ++ snd s ++ "))"
    mapM_ (\s -> putStrLn   $ "                          , (SC" ++ snd s ++ ", #const SCMP_SYS(" ++ snd s ++ "))") ss
    putStrLn                $ "                          ]"

genPrelude :: String
genPrelude = unlines $ [ "#include <stdio.h>"
                       , "#include \"syscallT.h\""
                       , "struct syscall_lookup_table {"
                       , "  int no;"
                       , "  const char* name;"
                       , "};"
                       ]
genLookupFunction :: String
genLookupFunction = unlines $ [ "const char* syscall_lookup(int no) {"
                              , "  if (no < 0 || no >= sizeof(syscall_lookup_tab) / sizeof(syscall_lookup_tab[0]))"
                              , "    return NULL;"
                              , "  return syscall_lookup_tab[no].name;"
                              , "}"
                              ]
printSyscallT :: [SyscallEntryDesc] -> IO ()
printSyscallT descs = putStrLn genPrelude >>
                      putStrLn "static const struct syscall_lookup_table syscall_lookup_tab[] = {" >>
                      mapM_ (\(x, y) -> putStrLn $ "  {" ++ show x ++ ", " ++ show y ++ "}, ") descs >>
                      putStrLn "};" >>
                      putStrLn genLookupFunction

main :: IO ()
main = printSyscallT =<< genSyscallTable
