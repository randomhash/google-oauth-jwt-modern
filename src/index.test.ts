import creds from '../creds.json';
import {obtainToken} from '.';

it('should return token', async () => {
  const token = await obtainToken({
    email: creds.client_email,
    key: creds.private_key,
    scopes: ['https://www.googleapis.com/auth/dialogflow'],
  });

  expect(token).toEqual(``);
});
