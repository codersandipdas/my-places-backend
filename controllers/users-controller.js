const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const HttpError = require('../models/http-error');
const User = require('../models/user');

const getUsers = async (req, res, next) => {
  let users;
  try {
    users = await User.find({}, '-password');
  } catch (err) {
    const error = new HttpError('Getting users failed!', 500);
    return next(error);
  }

  res.json({ users: users.map((user) => user.toObject({ getters: true })) });
};

const signup = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return next(
      new HttpError('Invalid Inputs Passed! Please Check Your Data.', 422)
    );
  }
  const { name, email, password } = req.body;

  // Checking if user with same email exists already
  let existingUser;
  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError('Signing Up failed, please try again!', 500);
    return next(error);
  }

  // If user already exists - through error
  if (existingUser) {
    const error = new HttpError(
      'This email is already registered, Please login instead.',
      422
    );
    return next(error);
  }

  let hashedPass;
  try {
    hashedPass = await bcrypt.hash(password, 12);
  } catch (err) {
    const error = new HttpError(
      'Could not create user, please try again!',
      500
    );
    return next(error);
  }

  // Creating new user
  const createdUser = new User({
    name,
    email,
    image: req.file.path,
    password: hashedPass,
    places: [],
  });

  // saving created user
  try {
    await createdUser.save();
  } catch (err) {
    const error = new HttpError('Signing Up failed, please try again!', 500);
    return next(error);
  }

  let token;
  try {
    token = jwt.sign(
      { userId: createdUser.id, email: createdUser.email },
      process.env.JWT_KEY,
      { expiresIn: '1h' }
    );
  } catch (err) {
    const error = new HttpError('Signing Up failed, please try again!', 500);
    return next(error);
  }

  res
    .status(201)
    .json({ userId: createdUser.id, email: createdUser.email, token: token });
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  // Checking if user with same email exists already
  let existingUser;
  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError('Login failed, please try again!', 500);
    return next(error);
  }

  // checking email and pass
  if (!existingUser) {
    const error = new HttpError('Invalid credentials!', 401);
    return next(error);
  }

  let isValidPass = false;
  try {
    isValidPass = await bcrypt.compare(password, existingUser.password);
  } catch (err) {
    const error = new HttpError(
      'Could not log in, please check your password again!',
      500
    );
    return next(error);
  }

  if (!isValidPass) {
    const error = new HttpError(
      'Could not log in, please check your password again!',
      500
    );
    return next(error);
  }

  let token;
  try {
    token = jwt.sign(
      { userId: existingUser.id, email: existingUser.email },
      process.env.JWT_KEY,
      { expiresIn: '1h' }
    );
  } catch (err) {
    const error = new HttpError('Logging in failed, please try again!', 500);
    return next(error);
  }

  res.json({
    userId: existingUser.id,
    email: existingUser.email,
    token: token,
  });
};

exports.getUsers = getUsers;
exports.signup = signup;
exports.login = login;
