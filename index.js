var crypto = require('crypto');

var BigInteger = require('bigi');
var ecurve = require('ecurve');

var ecparams = ecurve.getCurveByName('secp256k1');
var registrar = {
    privKey:"",
    blindingSession:{}
}

var generateRegristrarBlindingParams = function(){

    //Registrar chooses random numbers p, q within [1, n – 1]
    //and sends two EC points to Alice: P = (p -1 ·G) and Q = (q·p -1 ·G).
    var q = crypto.randomBytes(32);
    var r = crypto.randomBytes(32);

    var Q = ecparams.G.multiply(BigInteger.fromBuffer(q))
    var R = ecparams.G.multiply(BigInteger.fromBuffer(r))
    registrar.blindingSession[R.getEncoded(true).toString('hex')]={
        q:q,
        r:r
    };
    return {
        Q:Q.getEncoded(true).toString('hex'),
        R:R.getEncoded(true).toString('hex')
    }
}


var blindSign = function(blinded_hash, R)
{
	// signer generates signature (§4.3)
	var blindsig = BigInteger.fromBuffer(registrar.blindingSession[R].q).multiply(BigInteger.fromBuffer(blinded_hash)).add(BigInteger.fromBuffer(registrar.blindingSession[R].r)).bnMod(ecparams.n)
}

module.exports={
    blindSign:blindSign,
    generateRegristrarBlindingParams:generateRegristrarBlindingParams
}
