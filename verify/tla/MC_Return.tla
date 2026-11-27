------------------------------ MODULE MC_Return ------------------------------
(* A chain that comes back to the agent it started from: R (X) -> M (Y) -> K
   (X). The fourth audit's TestCrossDelegatedCascadesDoNotDeadlock, returning
   shape. C is a token Z is issued by exchanging K.                           *)
EXTENDS RevocationLocks, TLC

MC_Tok      == {"R", "M", "K", "C"}
MC_Parent   == "R" :> NoTok @@ "M" :> "R" @@ "K" :> "M" @@ "C" :> "K"
MC_Ident    == "R" :> "X" @@ "M" :> "Y" @@ "K" :> "X" @@ "C" :> "Z"
MC_OwnerOf  == "X" :> "u" @@ "Y" :> "v" @@ "Z" :> "w"
MC_Depth    == "R" :> 0 @@ "M" :> 1 @@ "K" :> 2 @@ "C" :> 3
MC_IssuedAt == "R" :> 10 @@ "M" :> 20 @@ "K" :> 30 @@ "C" :> 0
MC_Ord      == "R" :> 1 @@ "M" :> 2 @@ "K" :> 3 @@ "C" :> 4
MC_Stored0  == {"R", "M", "K"}
MC_Revoked0 == {}

MC_Procs    == {"issueC", "identZ", "identX", "identY", "singleM", "singleR", "ownerU"}
MC_Kind     == "issueC" :> "issue" @@ "identZ" :> "ident" @@ "identX" :> "ident" @@ "identY" :> "ident"
               @@ "singleM" :> "single" @@ "singleR" :> "single" @@ "ownerU" :> "owner"
MC_Target   == "issueC" :> "C" @@ "identZ" :> "Z" @@ "identX" :> "X" @@ "identY" :> "Y"
               @@ "singleM" :> "M" @@ "singleR" :> "R" @@ "ownerU" :> "u"
MC_Clock    == [p \in MC_Procs |-> {1, 40}]
=============================================================================
