const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = { logging: false };

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || 'postgres://localhost/auth_acme_db',
  config
);

const User = conn.define('user', {
  username: STRING,
  password: STRING,
});

User.addHook('beforeSave', async function (user) {
  // use ._changed property's set to determine if set has password - meaning if password hasn't changed, don't rehash it
  if (user._changed.has('password')) {
    user.password = await bcrypt.hash(user.password, 5);
  }
  //console.log(user._changed); // ._changed is an actual property that uses sets
});

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw' },
    { username: 'larry', password: 'larry_pw' },
    { username: 'moe', password: 'moe_pw' },
  ];
  const [lucy, larry, moe] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      larry,
      moe,
    },
  };
};

User.authenticate = async function ({ username, password }) {
  const user = await User.findOne({ where: { username } });
  if (user && (await bcrypt.compare(password, user.password))) {
    return jwt.sign({ id: user.id }, process.env.JWT);
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

User.byToken = async function (token) {
  try {
    const { id } = jwt.verify(token, process.env.JWT);
    const user = await User.findByPk(id);
    // this check verifies if the user exists
    if (user) {
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  } catch (ex) {
    // if you give me a token that is not sized correctly, not only am I gonna give you an error, but i am gonna give you an error with the correct status message
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

module.exports = {
  syncAndSeed,
  models: { User },
};
