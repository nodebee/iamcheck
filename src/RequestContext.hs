{-# LANGUAGE OverloadedStrings, MultiParamTypeClasses, TemplateHaskell, StandaloneDeriving, DeriveAnyClass, DeriveDataTypeable, DerivingVia, DeriveGeneric, FlexibleInstances, FunctionalDependencies, RecordWildCards #-}
module RequestContext
    ( RequestContext(..), SRequestContext, CRequestContext, sRPAnonymous, sRPIAMUser, sRPIAMRole, sRPService, sRPFederatedIdentity, sRPSAMLFederatedIdentity, sRPCanonicalUser, RequestPrincipal(..), prettyPrintRequestContext 
    ) where

import Data.SBV hiding (forAll_, forSome_, forAll, forSome)
import Data.SBV.Trans (MProvable, forAll_, forSome_, forAll, forSome)
import GHC.Generics
import Data.List (intercalate)

data RequestPrincipalType = 
  RPAnonymous | 
  RPIAMUser | 
  RPIAMRole | 
  RPService |
  RPFederatedIdentity |
  RPSAMLFederatedIdentity |
  RPCanonicalUser
mkSymbolicEnumeration ''RequestPrincipalType -- creates SRequestPrincipalType

data Resource str id resTypeEnum bool = Resource {
  resourcePresent :: bool,
  resourceId   :: id,
  resourceType :: resTypeEnum,
  resourceName :: str,
  resourceContains :: [id] 
  
} deriving (Show, Generic, Mergeable)

data RequestPrincipal typ str = RequestPrincipal {
  reqPrincipalType :: typ,
  reqPrincipalAccountId :: str,
  reqPrincipalName :: str,
  reqPrincipalFederationProvider :: str
} deriving (Show, Generic, Mergeable, Read)

data RequestContext typ str = RequestContext {
  reqAction :: str,
  reqServiceName :: str,
  reqResourceName :: str,
  reqPrincipal :: RequestPrincipal typ str
} deriving (Show, Generic, Mergeable, Read)

type SRequestContext = RequestContext SRequestPrincipalType SString
type CRequestContext = RequestContext RequestPrincipalType String

type SRequestPrincipal = RequestPrincipal SRequestPrincipalType SString
type CRequestPrincipal = RequestPrincipal RequestPrincipalType String

onRequestPrincipal :: ((typ -> str -> str -> str -> b) -> t) -> (RequestPrincipal typ str -> b) -> t
onRequestPrincipal f g = f ((fmap . fmap . fmap . fmap) g RequestPrincipal)
instance MProvable m p => MProvable m (SRequestPrincipal -> p) where
  forAll_   = onRequestPrincipal forAll_
  forSome_  = onRequestPrincipal forSome_
  forAll    = onRequestPrincipal . forAll
  forSome   = onRequestPrincipal . forSome 

onRequestContext :: ((str -> str -> str -> RequestPrincipal typ str -> b) -> t) -> (RequestContext typ str -> b) -> t
onRequestContext f g = f ((fmap . fmap . fmap . fmap) g RequestContext)
instance MProvable m p => MProvable m (SRequestContext -> p) where
  forAll_   = onRequestContext forAll_
  forSome_  = onRequestContext forSome_
  forAll    = onRequestContext . forAll
  forSome   = onRequestContext . forSome 

instance SatModel CRequestContext where
  parseCVs cvs = do
    (reqAction, cvs1) <- parseCVs cvs
    (reqServiceName, cvs2) <- parseCVs cvs1
    (reqResourceName, cvs3) <- parseCVs cvs2
    (reqPrincipal, cvs4) <- parseCVs cvs3
    return $ (RequestContext{..}, cvs4)
    
instance SatModel CRequestPrincipal where
  parseCVs cvs = do
    (reqPrincipalType, cvs1) <- parseCVs cvs
    (reqPrincipalAccountId, cvs2) <- parseCVs cvs1
    (reqPrincipalName, cvs3) <- parseCVs cvs2
    (reqPrincipalFederationProvider, cvs4) <- parseCVs cvs3
    return $ (RequestPrincipal{..}, cvs4)

prettyPrintRequestContext :: CRequestContext -> String
prettyPrintRequestContext (RequestContext action serviceName resourceName principal) = intercalate "\n" (linesToPrint ++ requestPrincipalToLines principal)
  where
    linesToPrint = ["Service name: " ++ (quote serviceName),
          "Action: " ++ (quote action),
          "Resource name: " ++ (quote resourceName)]
    requestPrincipalToLines (RequestPrincipal RPAnonymous _ _ _) = ["Principal: anonymous"]
    requestPrincipalToLines (RequestPrincipal RPIAMUser accId name _) = ["Principal: user " ++ quote (accId ++ ":" ++ name)]
    requestPrincipalToLines (RequestPrincipal RPIAMRole accId name _) = ["Principal: role " ++ quote (accId ++ ":" ++ name)]
    requestPrincipalToLines (RequestPrincipal RPService _ principalServiceName _) = ["Principal: service " ++ quote (principalServiceName)]
    requestPrincipalToLines (RequestPrincipal RPFederatedIdentity _ _ provider) = ["Principal: any principal authenticated by OIDC provider " ++ quote (provider)]
    requestPrincipalToLines (RequestPrincipal RPSAMLFederatedIdentity accId _ provider) = ["Principal: any principal authenticated by SAML provider " ++ quote (accId ++ ":" ++ provider)]
    requestPrincipalToLines (RequestPrincipal RPCanonicalUser _ userName _) = ["Principal: canonical user " ++ quote (userName)]

quote :: String -> String
quote s = "\"" ++ s ++ "\""
