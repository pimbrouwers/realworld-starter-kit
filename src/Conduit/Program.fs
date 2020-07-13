namespace Conduit

open Falco

module Program =        
    [<EntryPoint>]
    let main args =    
        try            
            Host.startWebHost 
                args
                (Server.configureWebHost Env.developerMode)
                [                    
                ]
            0
        with
        | _ -> -1