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

const { expect } = require('chai');
describe('Models', () => {
  let seed;
  beforeEach(async () => (seed = await syncAndSeed()));
  describe('seeded data', () => {
    it('there are 3 users', () => {
      expect(Object.keys(seed.users).length).to.equal(3);
    });
  });
  describe('User update', () => {
    describe('change username', () => {
      it('does not change the password', async () => {
        const password = seed.users.lucy.password;
        const lucy = seed.users.lucy;
        lucy.username = 'Looo';
        await lucy.save();
        expect(lucy.password).to.equal(password);
      });
    });
  });
  describe('User.authenticate', () => {
    describe('correct credentials', () => {
      it('returns a token', async () => {
        const token = await User.authenticate({
          username: 'moe',
          password: 'moe_pw',
        });
        expect(token).to.be.ok;
        console.log(token);
      });
    });
    describe('incorrect credentials', () => {
      it('throws an error', async () => {
        try {
          await User.authenticate({ username: 'moe', password: 'moe' });
          throw 'nooo!';
        } catch (ex) {
          expect(ex.status).to.equal(401);
          expect(ex.message).to.equal('bad credentials');
        }
      });
    });
  });
  describe('User.byToken', () => {
    describe('with a valid token', () => {
      it('returns a user', async () => {
        const token = await jwt.sign(
          { id: seed.users.larry.id },
          process.env.JWT //what happens here?
        );
        const user = await User.byToken(token); // look at method
        expect(user.username).to.equal('larry');
      });
    });
    describe('with a invalid token', () => {
      it('throws a 401', async () => {
        try {
          //if someone comes to the app and I use this method and they end up coming in here with an invalid token, an error will be thrown
          const token = await jwt.sign({ id: seed.users.larry.id }, 'whatever');
          await User.byToken(token);
          throw 'noooo';
        } catch (ex) {
          expect(ex.status).to.equal(401);
          expect(ex.message).to.equal('bad credentials');
        }
      });
    });
    describe('with a valid token but no associated user', () => {
      it('throws a 401', async () => {
        try {
          const token = await jwt.sign({ id: 99 }, process.env.JWT);
          await User.byToken(token);
          throw 'noooo';
        } catch (ex) {
          expect(ex.status).to.equal(401);
          expect(ex.message).to.equal('bad credentials');
        }
      });
    });
  });
});
