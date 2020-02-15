'use strict';

const express = require('express');
const router = express.Router();

const { check, validationResult } = require('express-validator');
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');

const User = require('./models').User;
const Course = require('./models').Course;


//error handler middleware for catching errors from unit 8 sql course/unit 9 REST APIS with Express calls try catch for async await functions so that they don't need to be done in each function. 
function asyncHandler(cb){
    return async (req, res, next) => {
      try {
            await cb(req, res, next)
      } catch(err){
            next(err);
        }
    }
}
//User authentication from unit 9's REST API Authentication with Express course. Verifies user credentials using bcrypt and basic-auth modules.
const authenticateUser = async (req, res, next) => {
    let message = null; 
    const users = await User.findAll();
    const credentials = auth(req);
    if (credentials) { 
      const user = users.find(user => user.emailAddress === credentials.name);
        if (user) { 
            const authenticated = bcryptjs.compareSync(credentials.pass, user.password);
              if (authenticated) { 
                 console.log(`Authentication successful for username: ${user.emailAddress}`);
                 req.currentUser = user; 
              } else {
                 message = `Authentication failure for username: ${user.emailAddress}`;
            }
        } else {
            message = `User not found for username: ${credentials.name}`; 
        }
    } else {
      message = 'Auth header not found';
    }
    if (message) {
      console.warn(message);
      res.status(401).json({ message: 'Access Denied ლ(ಠ_ಠლ)' });
    } else {
      next();
    }
  };

//USER Routes

// GET currently authenticated user hide sensitive information
router.get('/users', authenticateUser, asyncHandler(async (req,res)=> {
    const authUser = req.currentUser;
    const user = await User.findByPk(authUser.id, {
        attributes: { 
            exclude: [ 
                'password', 
                'createdAt', 
                'updatedAt'
            ] 
        },
    }); 
    if(user){
        res.status(200).json(user);
    } else {
        res.status(400).json({ message: "User not found (╯°□°)╯︵ ┻━┻ " });
    }

}));

//POST(CREATE) User, sets page to '/' displays no information
router.post('/users', asyncHandler(async (req,res)=> {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        res.status(400).json({ errors: errorMessages });
    } else {
        const user = req.body;
        if(user.password){
            user.password = bcryptjs.hashSync(user.password);
        }
        await User.create(req.body);
        res.status(201).location('/').end();
    }
   
}));

//COURSE ROUTES

// GET COURSES, Display created by, hide sensitive information.
router.get('/courses', asyncHandler(async (req, res)=>{
    const courses = await Course.findAll( {
        attributes: { 
            exclude: [
                'createdAt',
                'updatedAt'
            ] 
        },
        include: [ 
            {
                model: User,
                attributes: { 
                    exclude: [
                        'password', 
                        'createdAt', 
                        'updatedAt'
                    ] 
                },
            },
        ],
    });
    res.json(courses);

}));


// GET Courses by ID, exclude sensitive information
router.get('/courses/:id', asyncHandler(async (req, res)=>{

    const course = await Course.findByPk(req.params.id, {
        attributes: { 
            exclude: [ 
                'createdAt',
                'updatedAt'
            ] 
        },
        include: [ 
           {
               model: User,
               attributes: { 
                exclude: [
                    'password', 
                    'createdAt', 
                    'updatedAt'
                ] 
            },
           },
       ],
   });     
    res.status(200).json(course);
}));


// POST (CREATE) Course, set at new course Id route
router.post('/courses', authenticateUser, asyncHandler(async (req, res)=>{

    const course =  await Course.create(req.body);
    res.status(201).location('/courses/' + course.id).end(); 

}));


//PUT(Update) Courses, checks values, if empty throws errors
router.put('/courses/:id', authenticateUser, [ 
    check('title')
        .exists()
        .withMessage('Please provide a title'),
    check('description')
        .exists()
        .withMessage('Please provide a description'),
    check('userId')
        .exists()
        .withMessage('Please provide a value for "User Id"'),
] , asyncHandler(async (req, res, next)=> {
    const errors = validationResult(req);
    if(!errors.isEmpty()){ 
        const errorMessages = errors.array().map(error => error.msg);
        res.status(400).json({ errors: errorMessages });
    } else {
        const authUser = req.currentUser; 
        const course = await Course.findByPk(req.params.id);
        if(authUser.id === course.userId){ 
            await course.update(req.body);
            res.status(204).end(); 
        } else {
            res.status(403).json({message: "Sorry. You can only make changes to your own courses ¯\_(ツ)_/¯"});
        }

    }

}));


// DELETE Course ID, return no page 
router.delete('/courses/:id', authenticateUser, asyncHandler(async (req, res, next)=>{

    const authUser = req.currentUser; 
    const course = await Course.findByPk(req.params.id);
    if(course){
        if(authUser.id === course.userId){ 
            await course.destroy();
            res.status(204).end(); 
        } else {
            res.status(403).json({message: "Sorry. You can only make changes to your own courses ¯\_(ツ)_/¯"});
        }
    } else {
        next();
    }
}));


module.exports = router;