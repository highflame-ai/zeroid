------------------------------ MODULE MC_Chain ------------------------------
(* An orchestrator's token and a sub-agent's subtree: R (X) -> M (Y) -> L1, L2
   (Y). The third audit's TestOverlappingCascadesDoNotDeadlock shape, and the
   original race: C is a token Z is issued by exchanging M.                   *)
EXTENDS RevocationLocks, TLC

MC_Tok      == {"R", "M", "L1", "L2", "C"}
MC_Parent   == "R" :> NoTok @@ "M" :> "R" @@ "L1" :> "M" @@ "L2" :> "M" @@ "C" :> "M"
MC_Ident    == "R" :> "X" @@ "M" :> "Y" @@ "L1" :> "Y" @@ "L2" :> "Y" @@ "C" :> "Z"
MC_OwnerOf  == "X" :> "u" @@ "Y" :> "u" @@ "Z" :> "w"
MC_Depth    == "R" :> 0 @@ "M" :> 1 @@ "L1" :> 2 @@ "L2" :> 2 @@ "C" :> 2
MC_IssuedAt == "R" :> 10 @@ "M" :> 20 @@ "L1" :> 30 @@ "L2" :> 31 @@ "C" :> 0
MC_Ord      == "R" :> 1 @@ "M" :> 2 @@ "L1" :> 3 @@ "L2" :> 4 @@ "C" :> 5
MC_Stored0  == {"R", "M", "L1", "L2"}
MC_Revoked0 == {}

MC_Procs    == {"issueC", "identZ", "identX", "identY", "singleM", "singleR", "ownerU"}
MC_Kind     == "issueC" :> "issue" @@ "identZ" :> "ident" @@ "identX" :> "ident" @@ "identY" :> "ident"
               @@ "singleM" :> "single" @@ "singleR" :> "single" @@ "ownerU" :> "owner"
MC_Target   == "issueC" :> "C" @@ "identZ" :> "Z" @@ "identX" :> "X" @@ "identY" :> "Y"
               @@ "singleM" :> "M" @@ "singleR" :> "R" @@ "ownerU" :> "u"
MC_Clock    == [p \in MC_Procs |-> {1, 40}]
=============================================================================
