const express = require('express')
const router = express.Router();
const {registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser, getAllUsers, loginStatus, changeUserRole, sendAutomatedEmails, sendVerificationEmail, verifyUser, forgotPssword, sendLoginCode} = require('../controllers/text');
const { protect, adminOnly, authorOnly } = require('../middlewares/auth.middleware');
const { loginWithCode } = require('../controllers/user.controllers');

router.post('/register',registerUser)
router.get('/login',loginUser)
router.get('/logout',logoutUser)
router.get('/get-user',protect,getUser)
router.patch('/update-user',protect,updateUser)

router.delete('/:id',protect,adminOnly,deleteUser)
router.get('/get-all-users',protect,authorOnly,getAllUsers)
router.get('/login-status',loginStatus)
router.post('/change-user-role',protect,adminOnly,changeUserRole)
router.post('/send-automated-email',protect,sendAutomatedEmails)

router.post('/send-verification-email',protect,sendVerificationEmail)
router.patch('/verify-user/:verificationToken',protect,verifyUser)  
router.post('/forgot-password',forgotPssword)
router.patch('/reset-password/:resetToken',resetPassword)
router.patch("/changePassword", protect, changePassword);

router.post("/sendLoginCode/:email", sendLoginCode);
router.post("/loginWithCode/:email", loginWithCode);


module.exports = router;