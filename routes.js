'use strict';
const express = require('express');
const router = express.Router();

const {check, validationResult} = require('express-validator');
const bCrypt= require('bcryptjs');
const authentication = require('basic-auth');

const User = require('./models').User;
const Course = require('./models').Course;



function asyncHandler(cb){
    return async(req,res,next)=>{
        try{
            await cb(req,res,next)
        }catch(error){
            next(error);
        }
    }
}
const authUsers = async(req,res,next)=>{
    let message = null;
    const users = await User.findAll();
    const credentials = authentication(req);
        if(credentials){
            if(user){
                const user = users.find(user => user.emailAddress === credentials.name);
                const authenticated = bCrypt.compareSync(credentials.pass, user.password);
                if(authenticated){
                    console.log(`Authentication successful for User: ${user.emailAddress}`);
                    req.currentUser = user;
                    }else{
                    mesage= `Authenticatio failed for User${user.emailAddress}`;
                    }
            }else{
            message = `User not found for user: ${credentials.name}`;
            }
        }else{
        message= 'Authorization header not found';
    }
        if(message){
        console.warn(message);
        res.status(401).json({message: 'Access Denied'});
         } else{
            next();
        }
};
