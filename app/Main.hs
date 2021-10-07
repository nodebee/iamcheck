module Main (main) where

import Policy
import RequestContext (CRequestContext, prettyPrintRequestContext )
import AccessCheck (policyImplies, noPublicAccess, getCounterExample)

import Options.Applicative
import Data.ByteString (readFile)
import Control.Exception

data Arguments = ImplicationArguments {
  policyA :: String,
  policyB :: String
} | IsPublicArguments {
  policy :: String,
  accountId :: AWSAccountId
} deriving (Show)

data IAMCheckException = PolicyParseError String deriving Show
instance Exception IAMCheckException

parsedArgs :: Parser Arguments
parsedArgs = parseAsImplication <|> parseAsPublic
  where 
    parseAsImplication =  ImplicationArguments <$> 
      argument str (metavar "POLICY_FILE" <> help "filename of policy ") <*> 
      argument str (metavar "BOUNDARY_POLICY_FILE" <> help "filename of the boundary policy")
    parseAsPublic = IsPublicArguments <$> 
      argument str (metavar "POLICY_FILE") <*> 
      option (eitherReader parseAWSAccountIdToEither)
      ( long "accountId"
        <> short 'a'
        <> metavar "ACCOUNTID"
        <> help "account ID for checking public access (e.g. 123456789012)")

run :: Arguments -> IO ()
run (ImplicationArguments fileA fileB) = do
  parsedPolicyA <- readAndParse fileA
  parsedPolicyB <- readAndParse fileB
  policyImplies parsedPolicyA parsedPolicyB >>= return . getCounterExample >>= printResult
run (IsPublicArguments fileName accId) = do
  parsedPolicy <- readAndParse fileName
  noPublicAccess accId parsedPolicy >>= return . getCounterExample >>= printResult

printResult :: Maybe CRequestContext -> IO ()
printResult Nothing = putStrLn "Q.E.D."
printResult (Just context) = putStrLn $ "::: Counterexample found :::\n" ++ prettyPrintRequestContext context

readAndParse :: String -> IO Policy
readAndParse fn = Data.ByteString.readFile fn >>= return . parsePolicyEither >>= fromRightIO
  where
    fromRightIO :: Either String b -> IO b
    fromRightIO (Left err) = throwIO $ PolicyParseError $ "unable to parse file: " ++ fn ++ ", error: " ++ err
    fromRightIO (Right a) = return a

main :: IO ()
main = execParser opts >>= run
  where
    opts = info (parsedArgs <**> helper)
      ( fullDesc
     <> progDesc "Determines if every request permitted by the specified policy is also permitted by the boundary policy, or if the policy allows any access from outside the specified account ID."
     <> header "IAMCheck - a formal verification tool for AWS IAM policies" )

