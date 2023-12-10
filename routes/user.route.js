const express = require('express')
const router = express.Router();
const {registerUser, loginUser, logoutUser, getUser} = require('../controllers/user.controller');
const { protect } = require('../middlewares/auth.middleware');

router.post('/register',registerUser)
router.get('/login',loginUser)
router.get('/logout',logoutUser)
router.get('/get-user',protect,getUser)

module.exports = router;