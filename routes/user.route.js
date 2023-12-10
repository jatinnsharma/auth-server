const express = require('express')
const router = express.Router();
const {registerUser, loginUser, logoutUser} = require('../controllers/user.controller');

router.post('/register',registerUser)
router.get('/login',loginUser)
router.get('/logout',logoutUser)

module.exports = router;