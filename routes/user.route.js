const express = require('express')
const router = express.Router();
const {registerUser, loginUser, logoutUser, getUser, updateUser, deleteUser} = require('../controllers/user.controller');
const { protect, adminOnly } = require('../middlewares/auth.middleware');

router.post('/register',registerUser)
router.get('/login',loginUser)
router.get('/logout',logoutUser)
router.get('/get-user',protect,getUser)
router.patch('/update-user',protect,updateUser)

router.delete('/:id',protect,adminOnly,deleteUser)
router.get('/getUsers',protect,adminOnly,deleteUser)

module.exports = router;