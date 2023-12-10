const asyncHandler = require('express-async-handler')
const User = require('../models/user.models')
const { generateToken } = require('../utils')
const parser = require('ua-parser-js')
const bcrypt = require('bcryptjs')

// create user 
exports.registerUser = asyncHandler(async (req, res) => {
    const {name,email ,password} = req.body
    
    // Validation
    if(!name || !email || !password){
        res.status(400)
        throw new Error("Please fill in all the required fields.")
    }

    if(password.length < 6){
        res.status(400)
        throw new Error("Password must be up to 6 characters.")
    }

    // check if user exists
    const userExists = await User.findOne({email});

    if(userExists){
        res.status(400)
        throw new Error("Email is already in use.")
    }

    // Get UserAgent 
    const {ua} = parser(req.headers['user-agent']);
    const userAgent = [ua]

     // create new user 
     const user = await User.create({
        name,
        email,
        password,
        userAgent
     })

     // Generate Token
     const token = generateToken(user._id)

     // send HTTP-only cookie
     res.cookie('token',token,{
        path:'/',
        httpOnly:true,
        expires:new Date(Date.now()+1000 * 86400), // 1 day 
        sameSite:'none',
        secure:true
     })


     if(user){
        const {_id,name,email,bio,phone,photo,role,isVerified} = user;

        res.status(201).json({
            _id,name,email,bio,phone,photo,role,isVerified,token
        })
     }else{
        res.status(400);
        throw new Error('Invalid user data');
     }

     
});


// login user
exports.loginUser = asyncHandler(async (req,res)=>{
    const {email , password} = req.body;

    // validation 
    if(!email || !password){
        res.status(400);
        throw new Error('Please enter email and password!')
    }


    // check user exist 
    const user = await User.findOne({email});

    if(!user){
        res.status(404);
        throw new Error("User not found, please signup")
    }

    // check password is correct
    const passwordIsCorrect = await bcrypt.compare(password,user.password)

    if(!passwordIsCorrect){
        res.status(400);
        throw new Error('Invalid email or password')
    }

    // Trgger 2FA for unknow UserAgent 

    // Generate Token 
    const token = generateToken(user._id);

    if(user && password){
        // send HTTP-only cookie
        res.cookie('token',token,{
            path:'/',
            httpOnly:true,
            expires:new Date(Date.now()+1000 * 86400), // 1 day 
            sameSite:'none',
            secure:true
         })
         const {_id,name,email,bio,phone,photo,role,isVerified} = user;
     
         res.status(201).json({
             _id,name,email,bio,phone,photo,role,isVerified,token
         })
    }else{
        res.status(500);
        throw new Error('Something went wrong, please try again');
     }
})


exports.logoutUser= asyncHandler(async (req,res)=>{
    res.cookie('token',"",{
        path:'/',
        httpOnly:true,
        expires:new Date(0), // expire the cookie immediately
        sameSite:'none',
        secure:true
     })

     return res.status(200).json({message:"Logout successful"})
})

