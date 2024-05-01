use aiken/hash.{Blake2b_224, Hash}
use aiken/list
use aiken/transaction.{ScriptContext, Spend}
use aiken/transaction/credential.{VerificationKey}

type Datum {
  owner: VerificationKeyHash,
  beneficary: VerificationKeyHash,
  password: ByteArray,
}

type Redeemer {
  msg: ByteArray,
}

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

validator {
  fn match(datum: Datum, redeemer: Redeemer, context: ScriptContext) -> Bool {
    when context.purpose is {
      Spend(_) -> or {
          list.has(context.transaction.extra_signatories, datum.owner),
          and {
            redeemer.msg == datum.password,
            list.has(context.transaction.extra_signatories, datum.beneficary),
          },
        }
      _ -> False
    }
  }
}
