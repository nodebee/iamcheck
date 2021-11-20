{-# LANGUAGE TemplateHaskell, RecordWildCards #-}
module Validity (isValid) where

import Data.SBV (SString, SBool, (.==), (.&&), sAny, literal)
import RequestContext (SRequestContext, reqAction, reqServiceName)
import Data.FileEmbed (embedFile)
import Data.ByteString.Char8 (ByteString, split, lines, unpack)
import Data.Map (Map, toList, fromListWith)
import Data.Coerce (coerce)

allActionsFile :: ByteString
allActionsFile = $(embedFile "all-actions.txt") -- TODO: validate file compile-time

newtype AwsServiceActions = AwsServiceActions (Map ByteString [ByteString])

parsedActions :: ByteString -> AwsServiceActions
parsedActions actionsFile = coerce $ fromListWith (++) parsedLines
  where
    lineSplit line = Data.ByteString.Char8.split ':' line
    lineParsed line = ((lineSplit line) !! 0, pure $ (lineSplit line) !! 1)
    parsedLines = map lineParsed (Data.ByteString.Char8.lines actionsFile)

validActions :: AwsServiceActions
validActions = parsedActions allActionsFile

isValid :: SRequestContext -> SBool
isValid reqContext = sAny (\(svc, acts) -> service `equalToLiteral` svc .&& actionMatches action acts) (toList $ coerce validActions)
  where
    action = reqAction reqContext
    service = reqServiceName reqContext
    actionMatches symAction validActionList = sAny (equalToLiteral symAction) validActionList
    equalToLiteral :: SString -> ByteString -> SBool
    equalToLiteral sym = (.== sym) . literal . unpack

