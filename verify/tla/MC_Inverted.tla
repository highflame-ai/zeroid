------------------------------ MODULE MC_Inverted ------------------------------
(* A parent and child of the same identity at the same depth (a re-scoping
   exchange, a CIBA grant): R (Y) -> P (X) -> Q (X), P and Q both at depth 1.
   a row stored before this release: Q's issuing replica had a clock behind P's, so Q sorts first.
   C is a token Z is issued by exchanging Q.                                  *)
EXTENDS RevocationLocks, TLC

MC_Tok      == {"R", "P", "Q", "C"}
MC_Parent   == "R" :> NoTok @@ "P" :> "R" @@ "Q" :> "P" @@ "C" :> "Q"
MC_Ident    == "R" :> "Y" @@ "P" :> "X" @@ "Q" :> "X" @@ "C" :> "Z"
MC_OwnerOf  == "X" :> "u" @@ "Y" :> "v" @@ "Z" :> "w"
MC_Depth    == "R" :> 0 @@ "P" :> 1 @@ "Q" :> 1 @@ "C" :> 2
MC_IssuedAt == "R" :> 10 @@ "P" :> 20 @@ "Q" :> 19 @@ "C" :> 0
MC_Ord      == "R" :> 1 @@ "P" :> 2 @@ "Q" :> 3 @@ "C" :> 4
MC_Stored0  == {"R", "P", "Q"}
MC_Revoked0 == {}

MC_Procs    == {"issueC", "identX", "identY", "singleP", "singleQ", "ownerU"}
MC_Kind     == "issueC" :> "issue" @@ "identX" :> "ident" @@ "identY" :> "ident"
               @@ "singleP" :> "single" @@ "singleQ" :> "single" @@ "ownerU" :> "owner"
MC_Target   == "issueC" :> "C" @@ "identX" :> "X" @@ "identY" :> "Y"
               @@ "singleP" :> "P" @@ "singleQ" :> "Q" @@ "ownerU" :> "u"
MC_Clock    == [p \in MC_Procs |-> {1, 40}]
=============================================================================
