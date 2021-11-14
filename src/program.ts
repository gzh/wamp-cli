#!/usr/bin/env node

import { Connection,Session } from 'autobahn'
import { program } from 'commander'
import * as ed from 'ed25519'
import * as repl from './repl'
import 'colors'

const pkg = require('../package.json')

program
  .version(pkg.version)
  .arguments('<url> <realm> [role] [secret]')
  .action(start)
  .parse(process.argv)

function onchallenge(secret: string){
  return (_: Session, method: string, extra: any) => {
    if(method=='cryptosign'){
      let challenge = Buffer.from(extra['challenge'],'hex')
      let bsecret=Buffer.from(secret,'hex');
      let signature = ed.Sign(challenge,bsecret);
      return signature.toString('hex')+challenge.toString('hex');
    }
    else {
      throw new Error('Auth methods other than cryptosign are not supported')
    }
  }
}

function start(url: string, realm: string, role: string, secret: string) {
  let kp=ed.MakeKeypair(Buffer.from(secret,'hex'));
  let pubkey=kp.publicKey.toString('hex');
  const connection = new Connection({ url: url, realm: realm, authmethods:['cryptosign'], onchallenge: onchallenge(secret), authid: role,  authextra:{pubkey:pubkey}});
  connection.onopen = repl.start(connection)
  console.info(`Connecting to ${url} ${realm}`.italic.yellow)
  connection.open()
}
