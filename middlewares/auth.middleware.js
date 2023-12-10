const asyncHandler = require('express-async-handler')
const User = require('../models/user.models')
const jwt = require('jsonwebtoken')

exports.protect = asyncHandler(async(req,res,next)=>{
    try{
        // get user token 
        const token = req.cookies.token

        // check token is present or not 
        if(!token){
            res.status(400);
            throw new Error('Invalid email or password')
        }

        // Verify token 
        const Verified = jwt.verify(token, process.env.JWT_SECRET)

        // get user id from token 
        const user = await User.findById(Verified.id).select("-password")

        // if user not exits 
        if(!user){
            res.status(404);
            throw new Error("User not found");
        }
        
        // if user is suspended 
        if(user.role === 'suspended'){
            res.status(400);
            throw new Error("User suspended, please contact support");
        }
        req.user = user 
        next()
        
    }catch(error){
        res.status(401)
        console.error("Error",error)
        throw new Error("Not authorized , please login");
    }
})