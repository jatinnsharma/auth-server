const mongoose = require('mongoose')

;( async()=>{
       try{
        await mongoose.connect(process.env.MONGO_URI,{
            family:4
        });
        console.log("Database connected!");
       }catch(error){
        console.error(error);
        console.log("Something went wrong at database level")
        throw error;
        // process.exit(1) // exit from mongodb
       }
})()

module.exports =  mongoose