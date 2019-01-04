'use strict';
const g = require('strong-globalize')();

/**
* Phone model.  Extends LoopBack base [Model](#model-new-model).
* @property {String} to Phone phone number.  Required.
* @property {String} from Phone sender phone number.  Required.
* @property {String} text Text body of sms.
*
* @class Phone
* @inherits {Model}
*/

module.exports = function(Phone) {
  /**
   * Send an sms with the given `options`.
   *
   * Example Options:
   *
   * ```js
   * {
   *   from: "+123456789", // sender phone number
   *   to: "+123456789", // receiver phone number
   *   text: "Hello world", // plaintext body
   * }
   * ```
   *
   * @options {Object} options See below
   * @prop {String} from Senders's sms phone number
   * @prop {String} to recipient sms phone number
   * @prop {String} text Body text
   * @param {Function} callback Called after the sms is sent or the sending failed
   */

  Phone.send = function() {
    throw new Error(g.f('You must connect the {{Phone}} Model to a {{Phone}} connector'));
  };

  /**
   * A shortcut for Phone.send(this).
   */
  Phone.prototype.send = function() {
    throw new Error(g.f('You must connect the {{Phone}} Model to a {{Phone}} connector'));
  };
};
