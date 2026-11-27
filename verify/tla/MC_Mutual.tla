------------------------------ MODULE MC_Mutual ------------------------------
(* Two agents that delegate to each other: R1 (X) -> M1 (Y), R2 (Y) -> M2 (X).
   The fourth audit's TestCrossDelegatedCascadesDoNotDeadlock, mutual shape.
   C is a token Z is issued by exchanging M1.                                 *)
EXTENDS RevocationLocks, TLC

MC_Tok      == {"R1", "M1", "R2", "M2", "C"}
MC_Parent   == "R1" :> NoTok @@ "M1" :> "R1" @@ "R2" :> NoTok @@ "M2" :> "R2" @@ "C" :> "M1"
MC_Ident    == "R1" :> "X" @@ "M1" :> "Y" @@ "R2" :> "Y" @@ "M2" :> "X" @@ "C" :> "Z"
MC_OwnerOf  == "X" :> "u" @@ "Y" :> "u" @@ "Z" :> "w"
MC_Depth    == "R1" :> 0 @@ "M1" :> 1 @@ "R2" :> 0 @@ "M2" :> 1 @@ "C" :> 2
MC_IssuedAt == "R1" :> 10 @@ "M1" :> 20 @@ "R2" :> 11 @@ "M2" :> 21 @@ "C" :> 0
MC_Ord      == "R1" :> 1 @@ "M1" :> 2 @@ "R2" :> 3 @@ "M2" :> 4 @@ "C" :> 5
MC_Stored0  == {"R1", "M1", "R2", "M2"}
MC_Revoked0 == {}

MC_Procs    == {"issueC", "identZ", "identX", "identY", "singleR1", "ownerU"}
MC_Kind     == "issueC" :> "issue" @@ "identZ" :> "ident" @@ "identX" :> "ident" @@ "identY" :> "ident"
               @@ "singleR1" :> "single" @@ "ownerU" :> "owner"
MC_Target   == "issueC" :> "C" @@ "identZ" :> "Z" @@ "identX" :> "X" @@ "identY" :> "Y"
               @@ "singleR1" :> "R1" @@ "ownerU" :> "u"
MC_Clock    == [p \in MC_Procs |-> {1, 40}]
=============================================================================
