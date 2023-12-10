require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const PORT = process.env.PORT || 5000;
const userRoute = require('./routes/user.route')
const errorHandler = require('./middlewares/error.middleware')
require('./database')


const app = express();

//middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({extended:false}))
app.use(cookieParser());
app.use(
    cors({
        origin: ['http://localhost:3000',"https://auth-app.vercel.app"],
        credentials:true
    })
);

//routes 
app.use('/api/users',userRoute);

app.get('/',(req,res)=>{
    res.send('Home Page');
})

// Error Handler 
app.use(errorHandler);

app.listen(PORT,()=>{
    console.log(`Server is running on PORT ${PORT}`)
})