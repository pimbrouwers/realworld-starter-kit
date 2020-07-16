module Conduit.String

open System

let inline empty str = String.IsNullOrWhiteSpace(str)

let inline notEmpty str = not(empty str)