const express = require('express')
const router = express.Router()
const User = require('../models/User')
const dotenv = require("dotenv");
dotenv.config();
const { body, validationResult } = require('express-validator');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const jwtsecret = process.env.JWT_SECRET
router.post("/createuser", 
body('email').isEmail(),
body('name','Minimum Length: 5').isLength({ min: 5 }),
body('password','Incorrect Password').isLength({ min: 5 }),
async (req, res)=>{

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const salt =await bcrypt.genSalt(10);
    let secPassword = await bcrypt.hash(req.body.password, salt)
 
    try {
        await User.create({
            name: req.body.name,
            password:secPassword,
            email:req.body.email,
            location:req.body.location
        })

    res.json({success:true});
    } catch (error) {
        console.log(error)
        res.json({success:false});
    }
})

router.post("/loginuser", 
body('email').isEmail(),
body('password','Incorrect Password').isLength({ min: 5 }),
async (req, res)=>{

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {email, password}= req.body;

    try {
        let userData = await User.findOne({email});
        if (!userData)
        {
            return res.status(400).json({ errors: "Try logging with correct email" });
        }
        
        const pwdCompare = await bcrypt.compare(password, userData.password);
        if(!pwdCompare){
            return res.status(400).json({ errors: "Try logging with correct password" });
        }
        
        const data ={
            user:{
                id:userData.id
            }
        }

        const authToken = jwt.sign(data,jwtsecret)
        return res.json({ success: true,authToken:authToken })
    } 
    
    catch (error)
    {
        console.log(error)
        res.json({success:false});
    }
})

module.exports = router;
