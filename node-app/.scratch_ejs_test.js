const ejs = require('ejs');

// G1: verify SSTI now works with template-source embedding
function testEmailPreview(displayName) {
  const rawName = displayName || 'Customer';
  const emailTemplate = `<!DOCTYPE html>
<html><body>
  <p>Dear ${rawName},</p>
  <p>Thank you for your order.</p>
</body></html>`;
  try {
    return ejs.render(emailTemplate, {});
  } catch(e) {
    return 'Template error: ' + e.message;
  }
}

console.log('G1 INJ-03 SSTI test:');

const out1 = testEmailPreview('Alice');
console.log('  Normal name:', out1.includes('Dear Alice,') ? 'OK' : 'FAIL');

const out2 = testEmailPreview('<%= 7*7 %>');
console.log('  Probe <%= 7*7 %> renders 49:', out2.includes('Dear 49,') ? 'OK (SSTI works)' : 'FAIL: ' + out2.slice(0,200));

const out3 = testEmailPreview('<%= "hello".toUpperCase() %>');
console.log('  String method exec:', out3.includes('Dear HELLO,') ? 'OK (code exec)' : 'FAIL');

// Verify old approach did NOT work
function testOldApproach(displayName) {
  const emailTemplate = `<p>Dear <%= display_name %>,</p>`;
  try {
    return ejs.render(emailTemplate, { display_name: displayName });
  } catch(e) {
    return 'Template error: ' + e.message;
  }
}
const outOld = testOldApproach('<%= 7*7 %>');
console.log('\nOld approach (data-variable): produces "49"?', outOld.includes('49') ? 'YES (WRONG - should escape)' : 'NO - escapes to: ' + outOld);
