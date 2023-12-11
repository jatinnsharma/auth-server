const asyncHandler = require('express-async-handler')
const User = require('../models/user.models')
const { generateToken } = require('../utils')
const parser = require('ua-parser-js')
const bcrypt = require('bcryptjs')

// create user 
exports.registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body

    // Validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please fill in all the required fields.")
    }

    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must be up to 6 characters.")
    }

    // check if user exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400)
        throw new Error("Email is already in use.")
    }

    // Get UserAgent 
    const { ua } = parser(req.headers['user-agent']);
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
    res.cookie('token', token, {
        path: '/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day 
        sameSite: 'none',
        secure: true
    })


    if (user) {
        const { _id, name, email, bio, phone, photo, role, isVerified } = user;

        res.status(201).json({
            _id, name, email, bio, phone, photo, role, isVerified, token
        })
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }


});


// login user
exports.loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // validation 
    if (!email || !password) {
        res.status(400);
        throw new Error('Please enter email and password!')
    }


    // check user exist 
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found, please signup")
    }

    // check password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password)

    if (!passwordIsCorrect) {
        res.status(400);
        throw new Error('Invalid email or password')
    }

    // Trgger 2FA for unknow UserAgent 

    // Generate Token 
    const token = generateToken(user._id);

    if (user && password) {
        // send HTTP-only cookie
        res.cookie('token', token, {
            path: '/',
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day 
            sameSite: 'none',
            secure: true
        })
        const { _id, name, email, bio, phone, photo, role, isVerified } = user;

        res.status(201).json({
            _id, name, email, bio, phone, photo, role, isVerified, token
        })
    } else {
        res.status(500);
        throw new Error('Something went wrong, please try again');
    }
})


exports.logoutUser = asyncHandler(async (req, res) => {
    res.cookie('token', "", {
        path: '/',
        httpOnly: true,
        expires: new Date(0), // expire the cookie immediately
        sameSite: 'none',
        secure: true
    })

    return res.status(200).json({ message: "Logout successful" })
})


exports.getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    if (user) {
        const { _id, name, email, bio, phone, photo, role, isVerified } = user;
        res.status(201).json({
            _id, name, email, bio, phone, photo, role, isVerified
        })
    } else {
        res.status(404);
        throw new Error("User not found");
    }
})


exports.updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, bio, phone, photo, role, isVerified } = user;
        //  if the req.body.name hv name property then update the name else remain just as it is.
        user.email = email
        user.name = req.body.name || name
        user.phone = req.body.phone || phone
        user.bio = req.body.bio || bio
        user.photo = req.body.photo || photo

        // update the user 
        const updateUser = await user.save()

        res.status(201).json({
            _id: updateUser._id,
            name: updateUser.name,
            email: updateUser.email,
            bio: updateUser.phone,
            phone: updateUser.bio,
            photo: updateUser.photo,
            role: updateUser.role,
            isVerified: updateUser.isVerified
        })

    } else {
        res.status(404);
        throw new Error("User not found");
    }
})


// Delete user 
exports.deleteUser = asyncHandler( async (req,res) =>{
    const user = await User.findById(req.params.id);

    if(!user){
        res.status(404);
        throw new Error("User not found");
    }

    await user.deleteOne()

    res.status(200).json({message:"User deleted successfully"})
});

exports.getAllUsers = asyncHandler(async (req,res)=>{
    const users = await User.find().sort("-createdAt").select("-password")

    if(!users){
        res.status(500);
        throw new Error("Something went wrong");
    }

    res.status(200).json({users});
})

