import Test.HUnit

import TestPolicies
import Policy (parsePolicyEither, parsePolicy)
import AccessCheck (policyImplies, getCounterExample)
import Data.ByteString (ByteString)

import Data.Either (isRight)
import Data.Maybe (fromJust, isNothing)

testParsePolicy :: String -> ByteString -> Test
testParsePolicy policyName policy = TestCase $ isRight parsed @? "parsing " ++ policyName ++ " failed with: " ++ errorMsg
  where
    parsed = parsePolicyEither policy
    (Left errorMsg) = parsed

testPolicyImplies :: Bool -> String -> ByteString -> ByteString -> Test
testPolicyImplies expected policyName policy1 policy2 = TestCase $ isExpected @? "policyImplies " ++ policyName ++ " failed, expected: " ++ show expected 
  where
    result = policyImplies (parse policy1) (parse policy2) >>= (return . getCounterExample) 
    parse = fromJust . parsePolicy 
    isExpected :: IO Bool
    isExpected = do
      actual <- isNothing <$> result
      return (actual == expected)

expectPolicyImplies :: String -> ByteString -> ByteString -> Test
expectPolicyImplies = testPolicyImplies True

expectPolicyDoesNotImply :: String -> ByteString -> ByteString -> Test
expectPolicyDoesNotImply = testPolicyImplies False

main :: IO Counts
main = runTestTT $ TestList 
  [
    testParsePolicy "putObject" testJSONPutObject,
    testParsePolicy "condition" testJSONCondition,
    testParsePolicy "cloudwatch" testCloudWatch,
    expectPolicyImplies "allowPutObjectToAWSUser" allowPutObjectToAWSUser allowAllS3InAccount,
    expectPolicyDoesNotImply "allowPutObjectToAWSUserInAnotherAccount" allowPutObjectToAWSUserInAnotherAccount allowAllS3InAccount,
    expectPolicyDoesNotImply "allowChangePasswordToAWSUser" allowChangePasswordToAWSUser allowAllS3InAccount,
    expectPolicyImplies "principal pattern and condition are equal #1" allowPutObjectToAWSUser allowPutObjectToAWSUserByCondition,
    expectPolicyImplies "principal pattern and condition are equal #2" allowPutObjectToAWSUserByCondition allowPutObjectToAWSUser,
    expectPolicyImplies "allowing nonexisting action equals to empty #1" allowNonExistingAction empty,
    expectPolicyImplies "allowing nonexisting action equals to empty #2" empty allowNonExistingAction
  ] 
