{-# LANGUAGE OverloadedStrings, DeriveGeneric, DeriveAnyClass, RecordWildCards, FlexibleInstances, FlexibleContexts, GADTs, StandaloneDeriving, TemplateHaskell, PatternSynonyms, TypeApplications, ScopedTypeVariables #-}
module Policy where

import Data.Aeson
import Data.Aeson.Types
import Data.Text hiding (map, any, singleton, concat, take, drop)
import Control.Applicative ((<|>))
import Control.Monad (foldM)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Maybe (runMaybeT, MaybeT(..))
import GHC.Generics (Generic(..))
import Data.ByteString (ByteString)
import qualified Data.HashMap.Strict as HM
import Data.Foldable (fold)
import Data.Vector (toList)
import Data.Char (isDigit, isHexDigit)
import Data.SBV (SymVal)
import Data.GADT.Show.TH (deriveGShow)
import Type.Reflection (Typeable, typeOf, typeRep, pattern App, TypeRep)
import Data.Type.Equality ((:~:)(Refl), testEquality)
import Data.GADT.Show (GShow(..), gshow)
import Data.Scientific (Scientific, toBoundedInteger)
import Data.Functor ((<&>))
import Data.Coerce (coerce)

data TSome f = forall a. (Show a, SymVal a, Typeable a) => TSome (f a)

newtype AWSAccountId = AWSAccountId Text deriving (Show)

data Principal = 
  PrincipalAny 
  | PrincipalService !Text
  | PrincipalFederatedIdentity !Text  
  | PrincipalAWSAccount !AWSAccountId
  | PrincipalCanonicalUser !Text
  | PrincipalIAMUser {
    _IAMUserAccountId :: !Text,
    _IAMUserName :: !Text
  }
  | PrincipalIAMRole {
    _IAMRoleAccountId :: !Text,
    _IAMRoleName :: !Text
  }
  -- | PrincipalSession { -- TODO
  --   _IAMSessionRoleAccountId :: !Text,
  --   _IAMSessionRoleName :: !Text,
  --   _IAMSessionRoleSessionName :: !Text

  -- }
  | PrincipalFederatedSAMLUser {
    _SAMLAccountId :: !Text,
    _SAMLProviderName :: !Text
  }
  deriving (Show, Generic)

data ParsedARN = ParsedARN {
  _ARNPartition :: !Text,
  _ARNService :: !Text,
  _ARNRegion :: !Text,
  _ARNAccountId :: !Text,
  _ARNResourceId :: !Text
} deriving (Show)

newtype ParsedARNPattern = ParsedARNPattern ParsedARN deriving (Show)

data IAMResource = IAMUser !Text
  | IAMSamlProvider !Text
  | IAMRole !Text
  | IAMSession !Text !Text
  | IAMRoot

data ParsedAction = ParsedAction {
  _ActionService :: !Text,
  _ActionAction :: !Text
} deriving (Show)


data Effect = Allow | Deny deriving (Show, Generic, Eq, FromJSON, ToJSON)

data MaybeNegated a = NotNegated a | Negated a deriving (Show)

data Operator a where
  StringEquals :: Operator String
  StringNotEquals :: Operator String
  NumericEquals :: Operator Integer
  NumericNotEquals :: Operator Integer
deriving instance Show (Operator a)
deriveGShow ''Operator

data Variable a where
  AwsUserName :: Variable String
deriving instance Show (Variable a)
deriveGShow ''Variable

data ConditionKV a = (SymVal a, Show a) => ConditionKV (Variable a) [a]
deriving instance Show (ConditionKV a)
data Condition a = (SymVal a, Show a) => Condition (Operator a) [ConditionKV a]
deriving instance Show (Condition a)
deriveGShow ''Condition

data Statement = Statement {
  _Sid :: !(Maybe Text),
  _Principal :: !(MaybeNegated [Principal]),
  _Effect :: !Effect,
  _Action :: !(MaybeNegated [ParsedAction]),
  _Resource :: !(MaybeNegated [ParsedARNPattern]),
  _Condition :: ![TSome Condition]
} deriving (Show, Generic)

data Policy = Policy {
  _Version :: !Text,
  _Statement :: ![Statement]
} deriving (Show, Generic)

instance GShow p => Show (TSome p) where
  show (TSome p) = "TSome " ++ gshow p

-- todo: use kind-generics?
instance FromJSON (TSome Operator) where
  parseJSON (String "StringEquals") = return $ TSome StringEquals
  parseJSON (String "StringNotEquals") = return $ TSome StringNotEquals
  parseJSON (String "NumericEquals") = return $ TSome NumericEquals
  parseJSON (String "NumericNotEquals") = return $ TSome NumericNotEquals
  parseJSON _ = parseFail "unable parse condition operator"

instance FromJSON (TSome Variable) where
  parseJSON (String "aws:username") = return $ TSome AwsUserName
  parseJSON (String var) = parseFail $ "unrecognized condition variable: " ++ (unpack var)
  parseJSON _ = parseFail "unable to parse condition variable"

instance {-# OVERLAPPING #-} FromJSON ([TSome Condition]) where
  parseJSON = withObject "Condition" $ parseObjToList parseKV
    where
      parseKV :: (Text, Value) -> Parser (TSome Condition)
      parseKV (k, v) = do
        op <- parseJSON $ String k
        kv <- parseJSON v
        cond <- return $ makeCondition op kv
        fromJustOrFail "couldn't parse condition" cond

instance {-# OVERLAPPING #-} FromJSON ([TSome ConditionKV]) where
  parseJSON = withObject "ConditionKV" $ parseObjToList parseKV
    where 
    parseKV :: (Text, Value) -> Parser (TSome ConditionKV)
    parseKV (k, v) = do
      op <- parseJSON $ String k
      vList <- itemToList v
      kv <- parseListAsString vList <|> parseListAsNumeric vList
      cond <- return $ makeConditionKV op kv
      fromJustOrFail "couldn't parse conditionKV" cond
    parseListAsString :: [Value] -> Parser (TSome [])
    parseListAsString v = TSome . (map unpack) <$> (mapM parseJSON v)


    parseListAsNumeric :: [Value] -> Parser (TSome [])
    parseListAsNumeric v = mapM parseJSON v >>= mapM (fromJustOrFail "integer values are expected when parsing condition values as numeric" . scientificToInteger) <&> TSome

instance FromJSON Policy where
  parseJSON = genericParseJSON defaultOptions { fieldLabelModifier = Prelude.drop 1 }

instance FromJSON ParsedAction where
  parseJSON (String "*") = return $ ParsedAction "*" "*"
  parseJSON (String t) = doParse splitted
    where
      doParse [_ActionService, _ActionAction] = return $ ParsedAction {..}
      doParse _ = parseFail "unable to parse action"
      splitted = splitOn ":" t
  parseJSON _ = parseFail "invalid action"

instance FromJSON ParsedARNPattern where
  parseJSON (String "*") = return $ ParsedARNPattern $ ParsedARN "*" "*" "*" "*" "*"
  parseJSON item@(String _) = ParsedARNPattern <$> parseARN item
  parseJSON _ = parseFail "invalid ARN pattern"

fromJustOrFail :: MonadFail m => String -> Maybe a -> m a
fromJustOrFail _ (Just a) = return a
fromJustOrFail err Nothing = fail err

parseObjToList :: Monad m => ((Text, Value) -> m a) -> Object -> m [a]
parseObjToList parser obj = (return $ HM.toList obj) >>= mapM parser

scientificToInteger :: Scientific -> Maybe Integer
scientificToInteger v = toInteger <$> toBoundedInteger @Int v 

makeConditionKV :: TSome Variable -> TSome [] -> Maybe (TSome ConditionKV)
makeConditionKV (TSome var) (TSome val) = do
  Refl <- varType `testEquality` valType
  return $ TSome $ ConditionKV var val
  where
    App _ varType = typeOf var
    App _ valType = typeOf val

makeConditionKVList :: forall a. (Typeable a, SymVal a, Show a) => TypeRep a -> [TSome ConditionKV] -> Maybe [ConditionKV a]
makeConditionKVList p = foldM merge []
  where
    expectedItemType = App (typeRep @ConditionKV) p
    merge :: [ConditionKV a] -> TSome ConditionKV -> Maybe [ConditionKV a]
    merge acc (TSome item) = do
      Refl <- expectedItemType `testEquality` typeOf item
      return $ item : acc
  
makeCondition :: TSome Operator -> [TSome ConditionKV] -> Maybe (TSome Condition)
makeCondition (TSome op) condKVs = do
  condKVList <- makeConditionKVList opType condKVs
  return $ TSome $ Condition op condKVList
  where
    App _ opType = typeOf op

objToKVList :: Monad m => Object -> m [(Text, Value)]
objToKVList obj = return (HM.toList obj)

parseARN :: Value -> Parser ParsedARN
parseARN (String t) = doParse elements
  where 
    doParse ["arn", _ARNPartition, _ARNService, _ARNRegion, _ARNAccountId, _ARNResourceId] = return $ ParsedARN {..}
    doParse _ = parseFail "invalid ARN"
    splitted = splitOn ":" t
    arnElementsWithoutResourceId = take 5 splitted
    arnResourceId = intercalate ":" $ drop 5 splitted
    elements = arnElementsWithoutResourceId ++ [arnResourceId]
parseARN _ = parseFail "unable to parse ARN"

parsePrincipal :: Value -> Parser [Principal]
parsePrincipal (String "*") = return [PrincipalAny]
parsePrincipal (Object o) = do
  aws <- parsePrincipalMapEntry "AWS" parseAWSPrincipal
  federated <- parsePrincipalMapEntry "Federated" parseFederatedPrincipal
  service <- parsePrincipalMapEntry "Service" parseServicePrincipal
  canonical <- parsePrincipalMapEntry "CanonicalUser" parseCanonicalUserPrincipal
  return $ concat [fold federated, fold aws, fold service, fold canonical]
  where
    parsePrincipalMapEntry :: Text -> (Value -> Parser Principal) -> Parser (Maybe [Principal])
    parsePrincipalMapEntry field parser = runMaybeT $ MaybeT (o .:? field) >>= itemToList >>= lift . mapM parser
parsePrincipal _ = parseFail "couldn't parse principal"

parseAWSPrincipal :: Value -> Parser Principal
parseAWSPrincipal (String "*") = return PrincipalAny
parseAWSPrincipal item@(String s) = tryParseAccountId s <|> do
  arn <- parseARN item
  resource <- parseIAMResource (_ARNResourceId arn)
  toPrincipal resource arn
  where
    toPrincipal (IAMUser _IAMUserName) arn = return $ PrincipalIAMUser{_IAMUserAccountId = _ARNAccountId arn, ..}
    toPrincipal (IAMRole _IAMRoleName) arn = return $ PrincipalIAMRole{_IAMRoleAccountId = _ARNAccountId arn, ..}
    -- toPrincipal (IAMSession _IAMSessionRoleName _IAMSessionRoleSessionName) arn = return $ PrincipalSession{_IAMSessionRoleAccountId = _ARNAccountId arn, ..} --TODO
    toPrincipal (IAMRoot) arn = tryParseAccountId (_ARNAccountId arn)
    toPrincipal _ _ = parseFail "unable to parse AWS principal"
    tryParseAccountId :: Text -> Parser Principal
    tryParseAccountId accId = PrincipalAWSAccount <$> parseAWSAccountId accId
parseAWSPrincipal _ = parseFail "couldn't parse AWS principal"

parseAWSAccountId :: Text -> Parser AWSAccountId
parseAWSAccountId s | isValidAccountIdText s = return $ coerce s
  where
    isValidAccountIdText :: Text -> Bool
    isValidAccountIdText accId = Data.Text.all isDigit accId && Data.Text.length s == 12
parseAWSAccountId _ = parseFail "couldn't parse account ID"

parseAWSAccountIdToEither :: String -> Either String AWSAccountId
parseAWSAccountIdToEither = parseEither (parseAWSAccountId . pack)

itemToList :: Monad m => Value -> m [Value]
itemToList (Array v) = return $ toList v
itemToList other = return $ [other]

parseIAMResource :: Text -> Parser IAMResource
parseIAMResource t = doParse splitted
  where
    doParse ["root"] = return $ IAMRoot
    doParse ["user", user] = return $ IAMUser user
    doParse ["role", role] = return $ IAMRole role
    doParse ["saml-provider", provider] = return $ IAMSamlProvider provider
    doParse ["assumed-role", role, session] = return $ IAMSession role session
    doParse _ = parseFail "couldn't parse IAM resource specifier in ARN"
    splitted = splitOn "/" t

parseFederatedPrincipal :: Value -> Parser Principal
parseFederatedPrincipal item@(String _) = parseFederatedARN item <|> parseWebIdentityProvider item
  where
    parseFederatedARN v = do
      arn <- parseARN v
      (IAMSamlProvider _SAMLProviderName) <- parseIAMResource $ _ARNResourceId arn
      let _SAMLAccountId = _ARNAccountId arn
      return PrincipalFederatedSAMLUser{..}
    validIdentityProviders = ["cognito-identity.amazonaws.com", "www.amazon.com", "graph.facebook.com", "accounts.google.com"]
    parseWebIdentityProvider (String s) | any (== s) validIdentityProviders = return $ PrincipalFederatedIdentity s
    parseWebIdentityProvider _ = parseFail "invalid web identity provider"
parseFederatedPrincipal _ = parseFail "invalid federated principal"
    
parseServicePrincipal :: Value -> Parser Principal
parseServicePrincipal (String s) = return $ PrincipalService s
parseServicePrincipal _ = parseFail "unable to parse service principal"

parseCanonicalUserPrincipal :: Value -> Parser Principal
parseCanonicalUserPrincipal (String s) | Data.Text.all isHexDigit s = return $ PrincipalCanonicalUser s
parseCanonicalUserPrincipal _ = parseFail "invalid canonical user"

instance FromJSON Statement where
  parseJSON = withObject "statement" $ \o -> do
    _Sid <- o .:? "Sid"
    _Effect <- o .: "Effect"
    _Action <- (NotNegated <$> getAsList o "Action") <|> (Negated <$> getAsList o "NotAction")
    _Resource <- (NotNegated <$> getAsList o "Resource") <|> (Negated <$> getAsList o "NotResource")
    _Condition <- fold <$> (o .:? "Condition") 
    _Principal <- NotNegated <$> (o .: "Principal" >>= parsePrincipal) <|> Negated <$> (o .: "NotPrincipal" >>= parsePrincipal)
    return Statement{..}
      where
        getAsList o field = o .: field <|> (pure <$> o .: field)
    
parsePolicy :: ByteString -> Maybe Policy
parsePolicy = decodeStrict'

parsePolicyEither :: ByteString -> Either String Policy
parsePolicyEither = eitherDecodeStrict'

allowAllFromAccount :: AWSAccountId -> Policy
allowAllFromAccount accountId = Policy {_Version = "2012-10-17", _Statement = [Statement {_Sid = Just "Stmt1617054271329", _Principal = NotNegated [PrincipalAWSAccount accountId], _Effect = Allow, _Action = NotNegated [ParsedAction {_ActionService = "*", _ActionAction = "*"}], _Resource = NotNegated [ParsedARNPattern (ParsedARN {_ARNPartition = "aws", _ARNService = "*", _ARNRegion = "*", _ARNAccountId = "*", _ARNResourceId = "*"})], _Condition = []}]}
