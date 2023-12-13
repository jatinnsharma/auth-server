const jwt = require('jsonwebtoken')
const crypto = require('crypto')

// Generate token 
exports.generateToken =(id) =>{
    return jwt.sign(
        {id},
        process.env.JWT_SECRET,
        {expiresIn:'1d' }
    )
};

// hash token
exports.hashToken=(token)=>{
    return crypto.createHash('sha256').update(token.toString().digest('hex'))
}

