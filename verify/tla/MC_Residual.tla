------------------------------ MODULE MC_Residual ------------------------------
(* X delegates to Z and to Y, and Z delegates to Y: A (X) -> B (Z) -> S (Y).
   C is a new token for Y, issued by exchanging A, while X's and Y's tokens
   are revoked.                                                               *)
EXTENDS RevocationLocks, TLC

MC_Tok      == {"A", "B", "S", "C"}
MC_Parent   == "A" :> NoTok @@ "B" :> "A" @@ "S" :> "B" @@ "C" :> "A"
MC_Ident    == "A" :> "X" @@ "B" :> "Z" @@ "S" :> "Y" @@ "C" :> "Y"
MC_OwnerOf  == "X" :> "u" @@ "Y" :> "v" @@ "Z" :> "w"
MC_Depth    == "A" :> 0 @@ "B" :> 1 @@ "S" :> 2 @@ "C" :> 1
MC_IssuedAt == "A" :> 10 @@ "B" :> 20 @@ "S" :> 30 @@ "C" :> 0
MC_Ord      == "A" :> 1 @@ "B" :> 2 @@ "S" :> 3 @@ "C" :> 4
MC_Stored0  == {"A", "B", "S"}
MC_Revoked0 == {}

MC_Procs    == {"issueC", "identX", "identY", "singleA", "ownerV"}
MC_Kind     == "issueC" :> "issue" @@ "identX" :> "ident" @@ "identY" :> "ident"
               @@ "singleA" :> "single" @@ "ownerV" :> "owner"
MC_Target   == "issueC" :> "C" @@ "identX" :> "X" @@ "identY" :> "Y"
               @@ "singleA" :> "A" @@ "ownerV" :> "v"
MC_Clock    == [p \in MC_Procs |-> {1, 40}]
=============================================================================
