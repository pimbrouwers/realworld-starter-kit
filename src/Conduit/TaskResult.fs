module Conduit.TaskResult 

open System.Threading.Tasks
open FSharp.Control.Tasks

module Task =        
    let retn value = 
        value 
        |> Task.FromResult

    let bind (f : 'a -> Task<'b>) (x : Task<'a>) = 
        task {
            let! x = x
            return! f x
        }

    let map f x = 
        x 
        |> bind (f >> retn)

type TaskResult<'Ok, 'Error> = Task<Result<'Ok, 'Error>>

/// Lift a value to AsyncResult
let retn x : TaskResult<_,_> = 
    x |> Result.Ok |> Task.retn

/// Apply a monadic function to an TaskResult value  
let bind (f : 'a -> TaskResult<'b,'c>) (xTaskResult : TaskResult<_, _>) : TaskResult<_,_> = 
    task {
        let! xResult = xTaskResult 
        match xResult with
        | Ok x -> return! f x
        | Error err -> return (Error err)
    }

/// Lift a function to TaskResult
let map f (x : TaskResult<_,_>) : TaskResult<_,_> =
    Task.map (Result.map f) x

/// Lift a function to TaskResult
let mapError f (x : TaskResult<_,_>) : TaskResult<_,_> =
    Task.map (Result.mapError f) x

/// Lift a Result into an TaskResult
let ofResult x : TaskResult<_,_> = 
    x |> Task.retn

/// Lift a Task into an TaskResult
let ofTask x : TaskResult<_,_> = 
    x |> Task.map Result.Ok  