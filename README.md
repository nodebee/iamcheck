IAMCheck
========

IAMCheck allows you to verify properties of AWS IAM policies. It works by converting IAM policies into an SMT encoding and using an SMT solver (e.g. Z3 or CVC4) to prove that the property holds or to generate a counterexample.


# Usage

IAMCheck can prove implication between policies, i.e. that for every request allowed by a policy, it is always allowed by a second policy. You can use this to define properties as a set of simple, easy-to-audit boundary policies and prove that the actual policy implies them.

A typical use-case is to verify that a policy doesn't allow anonymous access (i.e. access from any account other that a trusted one). To verify that, we prove that our policy is strictly more restrictive than a policy that allows all access from the trusted account, but none from anywhere else. Such a boundary policy might look like this:

```
{ 
  "Version": "2012-10-17", 
  "Statement": [ 
    { 
      "Sid": "Stmt1617054271329", 
      "Principal": {"AWS": "123456789012"}, 
      "Action": "*", 
      "Effect": "Allow", 
      "Resource": "*" 
    } 
  ] 
}
```

To prove this, run IAMCheck as:
```
iamcheck policy.json boundary_policy.json
```

The output might look like the following:
```
::: Counterexample found :::
Service name: "s3"
Action: "GetObject"
Resource name: "test3"
Principal: anonymous
```

indicating that objects in the "test3" S3 bucket are readable as anonymous, violating the intended property.

To simplify checking for anonymous access, IAMCheck provides the `-a` argument that takes the trusted account ID, thus writing the policy above is equivalent to running the following:

```
iamcheck -a 123456789012 policy.json
```

Note that IAMCheck expects policies to include a Principal or NotPrincipal field. You might need to explicitly add this to identity-based policies.

## Positive access checks

You can also use IAMCheck to verify that a policy does allow access, e.g. to prevent outages resulting from mistakenly revoked permissions. The usage is the same as shown above, except in this case the policy describing the property is passed as the first parameter:
```
iamcheck property.json policy.json
```
# Building and dependencies

IAMCheck is a stack project and once [stack](https://docs.haskellstack.org/en/stable/README/) is installed, can be built with:
```
stack build
```

Binaries are created under the stack dist dir:
```
$(stack path --dist-dir)/build/iamcheck-exe/iamcheck-exe
```

IAMCheck also needs [Z3](https://github.com/Z3Prover/z3) 4.8.12 or later.

# Supported features
IAMCheck supports the most commonly used parts of the IAM policy specification, including negated statements (e.g. NotPrincipal, NotResource, etc), wildcards and conditions. Currently only the condition operators `StringEquals` and `StringNotEquals` and the condition variable `aws:username` is supported.

# FAQ

## How it is different from...
### AWS Access Analyzer

IAMCheck is very similar to (and was inspired by) the internal AWS service behind Access Analyzer, [Zelkova](https://www.cs.utexas.edu/users/hunt/FMCAD/FMCAD18/papers/paper3.pdf). The primary difference is that while Zelkova is a proprietary service you can't even directly access, IAMCheck is open source.

### AWS Permission Boundaries and SCPs

IAMCheck allows you to verify that a policy will not grant unintended access, while permission boundaries and SCPs restrict access to achieve the same effect. The advantage of IAMCheck's static approach is that (unlike SCPs) there is no limit to the number of checks that can be run and that it provides feedback upfront, instead of having to debug a failing request in an actual system; the disadvantage is that IAMCheck can't enforce any properties if e.g. an attacker is able to modify a policy directly.
