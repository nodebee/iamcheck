{-# LANGUAGE OverloadedStrings, GADTs #-}
module AccessCheck (policyImplies, noPublicAccess, getCounterExample) where

import RequestContext
import Data.SBV
import Data.SBV.RegExp
import Data.Text (Text, unpack)
import Data.List (unfoldr)
import Data.Coerce (coerce)
import Validity (isValid)

import qualified Policy as P

accessControlCheck :: P.Policy -> SRequestContext -> SBool
accessControlCheck policy reqContext = sAny (statementMatches reqContext) allowStatements .&& sNot (sAny (statementMatches reqContext) denyStatements) 
  where 
    allowStatements :: [P.Statement]
    allowStatements = filter (\x -> P._Effect x == P.Allow) $ P._Statement $ policy
    denyStatements :: [P.Statement]
    denyStatements = filter (\x -> P._Effect x == P.Deny) $ P._Statement $ policy

statementMatches :: SRequestContext -> P.Statement -> SBool
statementMatches reqContext statement = (matchMaybeNegated actionMatcher $ P._Action statement) .&& (matchMaybeNegated arnMatcher $ P._Resource statement) .&& (matchMaybeNegated principalMatcher $ P._Principal statement) .&& conditionMatcher (P._Condition statement)
  where
    actionMatcher = sAny (matchAction reqContext)
    arnMatcher = sAny (matchARN reqContext)
    principalMatcher = sAny (matchPrincipal reqContext) 
    conditionMatcher [] = sTrue
    conditionMatcher conditions = sAny (evaluateCondition reqContext) conditions

matchAction :: SRequestContext -> P.ParsedAction -> SBool
matchAction reqContext action = reqServiceName reqContext `matchRegex` svcPattern .&& reqAction reqContext `matchRegex` actionPattern
  where
    svcPattern = P._ActionService action
    actionPattern = P._ActionAction action

matchARN :: SRequestContext -> P.ParsedARNPattern -> SBool
matchARN reqContext arn = reqServiceName reqContext `matchRegex` svcPattern .&& reqResourceName reqContext `matchRegex` resourcePattern
  where
    svcPattern = P._ARNService $ coerce arn
    resourcePattern = P._ARNResourceId $ coerce arn

matchPrincipal :: SRequestContext -> P.Principal -> SBool
matchPrincipal reqContext principal = case principal of
  P.PrincipalAny -> sTrue
  P.PrincipalIAMUser accountId user -> principalType .== sRPIAMUser .&& principalName .== toLiteral user .&& reqAccountId .== toLiteral accountId
  P.PrincipalIAMRole accountId role -> principalType .== sRPIAMRole .&& principalName .== toLiteral role .&& reqAccountId .== toLiteral accountId
  P.PrincipalAWSAccount accountId -> (principalType .== sRPIAMUser .|| principalType .== sRPIAMRole) .&& reqAccountId .== (toLiteral . coerce) accountId
  P.PrincipalService serviceName -> principalType .== sRPService .&& principalName .== (toLiteral . coerce) serviceName
  P.PrincipalFederatedIdentity provider -> principalType .== sRPFederatedIdentity .&& federationProvider .== toLiteral provider
  P.PrincipalFederatedSAMLUser accountId provider -> principalType .== sRPSAMLFederatedIdentity .&& reqAccountId .== toLiteral accountId .&& federationProvider .== toLiteral provider
  P.PrincipalCanonicalUser userName -> principalType .== sRPCanonicalUser .&& principalName .== toLiteral userName
  where
    principalType = reqPrincipalType $ reqPrincipal reqContext
    principalName = reqPrincipalName $ reqPrincipal reqContext
    reqAccountId = reqPrincipalAccountId $ reqPrincipal reqContext
    federationProvider = reqPrincipalFederationProvider $ reqPrincipal reqContext

toLiteral :: Text -> SString
toLiteral = literal . unpack

matchMaybeNegated :: (a -> SBool) -> P.MaybeNegated a -> SBool
matchMaybeNegated matcher (P.NotNegated a) = matcher a
matchMaybeNegated matcher (P.Negated a) = sNot $ matcher a

getFromReqContext :: SRequestContext -> P.Variable a -> (SBool, (SBV a))
getFromReqContext reqContext variable = case variable of
  (P.AwsUserName) -> (reqPrincipalType principal .== sRPIAMUser, reqPrincipalName principal)
  where
    principal = reqPrincipal reqContext

evaluateCondition :: SRequestContext -> P.TSome P.Condition -> SBool
evaluateCondition reqContext (P.TSome cond) = sAny (evaluateConditionKV reqContext op) conditionKVs
  where
    (P.Condition op conditionKVs) = cond

evaluateConditionKV :: SymVal a => SRequestContext -> P.Operator a -> P.ConditionKV a -> SBool
evaluateConditionKV reqContext op (P.ConditionKV var values) = reqVarPresent .&& (sAny (condOperator op reqVar) $ map literal values)
  where
    (reqVarPresent, reqVar) = getFromReqContext reqContext var

condOperator :: P.Operator a -> (SBV a) -> (SBV a) -> SBool
condOperator (P.StringEquals) a b = a .== b
condOperator (P.StringNotEquals) a b = sNot (a .== b)
condOperator (P.NumericEquals) a b = a .== b
condOperator (P.NumericNotEquals) a b = sNot (a .== b)

matchRegex :: SBV String -> Text -> SBool
matchRegex a b = a `match` (resourcePatternToRegex $ unpack b)

separateBy :: Eq a => [a] -> [a] -> [[a]]
separateBy chrs = unfoldr sep where
  sep [] = Nothing
  sep l@(hd:tl) 
    | Prelude.elem hd chrs = Just ([hd], tl)
    | otherwise = Just . (break (flip Prelude.elem chrs)) $ l

resourcePatternToRegex :: String -> RegExp
resourcePatternToRegex = Conc . (fmap simbolify) . (separateBy ['*','?'])
  where
    simbolify "*" = KStar All
    simbolify "?" = All
    simbolify s = Literal s

policyImplies :: P.Policy -> P.Policy -> IO ThmResult
policyImplies p1 p2 = prove $ implication p1 p2
  where
    implication a b reqContext = ((accessControlCheck a reqContext .&& isValid reqContext) .=> accessControlCheck b reqContext )

noPublicAccess :: P.AWSAccountId -> P.Policy -> IO ThmResult
noPublicAccess accountId policy = policyImplies policy (P.allowAllFromAccount accountId)

getCounterExample :: ThmResult -> Maybe CRequestContext
getCounterExample = extractModel

