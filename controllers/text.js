const asyncHandler = require('express-async-handler')
const User = require('../models/user.schema')
const { generateToken, hashToken } = require('../utils')
const parser = require('ua-parser-js')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const sendEmail = require('../utils/sendEmail')
const crypto = require('crypto')
const Token = require('../models/token.schema')
const Cryptr = require('cryptr');


const cryptr = new Cryptr(process.env.CRYPTR_KEY);

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
     const ua = parser(req.headers["user-agent"]);
     const thisUserAgent = ua.ua;
     console.log(thisUserAgent)
     const allowedAgent = user.userAgent.includes(thisUserAgent)

     if(!allowedAgent){
        // Generate 6 digit code 
        const loginCode = Math.floor(100000 + Math.random()*900000)

        // Encrypt login code before saving to db 
        const encrytedLoginCode = cryptr.encrypt(loginCode.toString())

        // delete token if it exists in db 
        let userToken = await Token.findOne({userId:user._id});
        if(userToken){
            await token.deleteOne();
        }

        // save token to db 
        await new Token({
           userId:user._id,
           lToken:encrytedLoginCode,
           createdAt:Date.now(),
           expiresAt:Date.now() + 60 * (60 * 1000), // 60 mins
        }).save();

        res.status(400);
        throw new Error("New browser or deivce detected");
     }
// Send login code
exports.sendLoginCode = asyncHandler (async (req,res)=>{
    const {email} = req.params

    const user = await User.findOne({email});

    if(!user){
        res.status(404)
        throw new Error("User not found")
    }

    // Find Login code in db 
    let userToken = await Token.findOne({userId:user._id});

    if(!userToken){
        res.status
    }
})

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

// send verification email
exports.sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error("user already verified");
    }

    // Delete token if it exists in db 
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    // create verification token and save 
    const verificationToken = crypto.randomBytes(32).toString('hex') + user._id;
    console.log(verificationToken);

    // hash token 
    const hashedToken = hashToken(verificationToken)

    await new Token({
        userId: user._id,
        verifyToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins 
    }).save()

    // construct verification URL 
    const verificationURL = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

    // send email 
    const subject = "Verify Your Account - AUTH-Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@zino.com";
    const template = "verifyEmail";
    const name = user.name;
    const link = verificationURL;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Verification Email Sent" });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }
})

// verify user
exports.verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    const hashedToken = hashToken(verificationToken)

    const userToken = await Token.findOne(
        {
            verifyToken: hashedToken,
            expiresAt: { $gt: Date.now() }
        }
    )
    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    // Find user
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified == true) {
        res.status(404);
        throw new Error("User is already verified")
    }

    // Now verify user
    user.isVerified = true;
    await user.save();

    res.status(200).json({ messsage: "Account Verification Successful" })
})

// Forgot Password 
exports.forgotPssword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("No user with this email");
    }

    // Delete token if it exists in db
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    // create verification token and save 
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken);

    // Hash token and save
    const hashedToken = hashToken(resetToken);
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save();

    // Construct Reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  // Send Email
  const subject = "Password Reset Request - AUTH:Z";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@zino.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Password Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
})

exports.resetPassword = asyncHandler(async (req,res)=>{
    const {resetToken} = req.params;
    const {password} = req.body;

    const hashedToken = hashToken(resetToken);

    const userToken = await Token.findOne(
        {
            resetToken:hashedToken,
            expiresAt:{$gt:Date.now()},
        }
    );

    if(!userToken){
        res.status(404);
        throw new Error("Invalid or Expired Token");  
    }

    // find user 
    const user = await User.findOne({_id:userToken.userId})

    // Now Reset password
    user.password = password;
    await user.save();

    res.status(200).json({ message: "Password Rest Successful, please login" });
})


exports.changePassword = asyncHandler(async (req,res)=>{
    const {oldPassword,password} = req.body;

    const user = await User.findOne(req.user._id);
    if(!user){
        res.status(404);
        throw new Error("User not found");
    }

    if(!oldPassword || !password){
        res.status(400);
        throw new Error("Please enter old and new password");
    }
    
    // check if old password is correct 
    const passwordIsCorrect = await bcrypt.compare(oldPassword,user.password);

    // save new password
     // Save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();

    res
      .status(200)
      .json({ message: "Password change successful, please re-login" });
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
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
exports.deleteUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    await user.deleteOne()

    res.status(200).json({ message: "User deleted successfully" })
});

// get all users data 
exports.getAllUsers = asyncHandler(async (req, res) => {
    const users = await User.find().sort("-createdAt").select("-password")

    if (!users) {
        res.status(500);
        throw new Error("Something went wrong");
    }

    res.status(200).json({ users });
})

// login status
exports.loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }
    // verify token 
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    }
    return res.json(false);
})

// change user role 
exports.changeUserRole = asyncHandler(async (req, res) => {
    const { role, id } = req.body

    const user = await User.findById(id);

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    user.role = role;
    await user.save()

    res.status(200).json({ message: `User role updated to ${role}` })
});

// send Automated emails 
exports.sendAutomatedEmails = asyncHandler(async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500);
        throw new Error("Missing email parameter");
    }

    // Get user
    const user = await User.findOne({ email: send_to });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = `${process.env.FRONTEND_URL}${url}`;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ message: "Email Sent" });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }
})

