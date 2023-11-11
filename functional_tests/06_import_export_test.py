#!/usr/bin/env python
import unittest
import requests
import time
import json

VAULT_ID1 = ''
VAULT_ID2 = ''
JWT_TOKEN = ''
SERVER='https://localhost:8443'

DATA1 = """Type,name,url,username,password,note,totp,category
Login,Youtube,https://www.youtube.com/,youlogin,youpassword,tempor incididunt ut labore et,,
Login,Amazon      ,https://www.amazon.com/,amlogin1,ampassword1,sit amet, consectetur adipiscing,,
Login,Bank of America ,https://www.boa.com/,mylogin3,mypassword3,Excepteur sint occaecat cupidatat non,,
Login,Twitter     ,https://www.twitter.com/,mylogin3,mypassword3,eiusmod tempor incididunt ut,,
Login,AT&T,https://www.att.com/,mylogin4,mypassword4,mynote4,,
Login,All State Insurance,https://www.allstate.com/,mylogin5,mypassword5,do eiusmod tempor incididunt ut,,
Login,Microsoft,https://www.microsoft.com/,mylogin7,mypassword7,ed do eiusmod tempor incididunt ut,,
Secure Note,Personal Note name,,,,My Secure Note,,
Secure Note,Social Note name1,,,,My Secure Note1,,
Secure Note,Work Note name2,,,,My Secure Note2,,
Secure Note,Reminder Note name3,,,,My Secure Note3,,
Secure Note,TODO Note name4,,,,My Secure Note4,,
Secure Note,Plan Note name5,,,,My Secure Note5,,
Login,Netflix,https://www.netflix.com/,mylogin6,mypassword6,mynote6,,
Login,Facebook,https://www.facebook.com/,mylogin8,mypassword8,mynote8,,
Login,Twitch,https://twitch.tv/,mylogin6,mypassword6,mynote6,,"""


DATA2 = """Type,name,url,username,password,email,description,note,category,tags,otp,icon,renew_interval_days,expires_at
Login,Github,https://github.com,alice,Alice#12Wonderland%,alice@wonder.land,,null,Chat,,,,,
Login,,books.io,bob,Bob#12Books%,,,,,,,,,
Login,Youtube,https://www.youtube.com/,youlogin,youpassword,,,sed do eiusmod tempor incididunt,,,,,,
Login,Amazon,https://www.amazon.com/,amlogin1,ampassword1,id123@amazon.com,am - desc,amnote1,Open this select menu,,,,,
Login,Citibank,https://www.citibank.com/,citylogin3,citypassword3,,,sed do eiusmod tempor incididunt,,,,,,
Login,Twitter     ,https://www.twitter.com/,mylogin3,mypassword3,,,Lorem ipsum dolor sit amet,,,,,,
Login,AT&T,https://www.att.com/,mylogin4,mypassword4,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",Logins,"a1, a2",,,,
Login,All State Insurance,https://www.allstate.com/,mylogin5,mypassword5,,,,Logins,,,,,
Login,Microsoft,https://www.microsoft.com/,mylogin7,mypassword7,,,mynote7,,,,,,
Notes,Personal Note name,,,,,,Morbi non arcu risus quis varius  Note,,,,,,
Notes,Social Note name1,,,,,,My Secure sed do eiusmod tempor,,,,,,
Notes,Work Note name2,,,,,,My Secure NMagna fringilla urna porttitor rhoncus,,,,,,
Notes,Reminder Note name3,,,,,,My Secure At tempor commodo ullamcorper a lacus ,,,,,,
Notes,TODO Note name4,,,,,,My Secure Aliquam vestibulum morbi blandit cursus ,,,,,,
Notes,Plan Note name5,,,,,,My Secure Pellentesque nec nam aliquam,,,,,,
Login,Netflix,https://www.netflix.com/,mylogin6,mypassword6,,,mynote6,,,,,,
Login,Facebook,https://www.facebook.com/,mylogin8,mypassword8,,,my notes,Open this select menu,"fb1, fb2",,,,
Login,Twitch,https://twitch.tv/,mylogin6,mypassword6,,,mynote6,,,,,,
Login,chips,https://www.newegg.com,chips2,chips3,chips@egg.io,chips1,chips chips,Gaming,egg,,,,
Login,fidelity,https://www.fidelity.org/,login1,password1,you@gm.io,,Lorem ipsum dolor sit amet,,,,,,
Login,vanguard,https://www.vanguard.com/,amlogin1,ampassword1,you@gm.io,,consectetur adipiscing elit,,,,,,
Login,Citibank,https://www.citibank.com/,mylogin3,mypassword3,alice@citi.io,,sed do eiusmod tempor incididunt ut labore et dolore magna aliqua,,,,,,
Login,CVS Health,https://www.cvshealth.com/,mylogin3,mypassword3,bob@io.com,,quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat,,,,,,
Login,Humble Bundle,https://www.humblebundle.com/,mylogin4,mypassword4,alice@bundle.io,,Excepteur sint occaecat cupidatat non proident,,,,,,
Login,Gap,https://www.gap.com/,mylogin5,mypassword5,me@gap.com,,Lorem ipsum dolor sit amet,,,,,,
Login,CBS,https://www.cbs.com/,mylogin7,mypassword7,me@cbs.io,,consectetur adipiscing elit,,,,,,
Notes,Personal Note name,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Mattis nunc sed blandit libero volutpat sed cras ornare arcu. Dictum non consectetur a erat nam. Ut morbi tincidunt augue interdum velit. Vel fringilla est ullamcorper eget. Hendrerit dolor magna eget est lorem ipsum dolor sit. Aliquet risus feugiat in ante metus dictum at tempor. Sapien nec sagittis aliquam malesuada bibendum. Eu nisl nunc mi ipsum. At risus viverra adipiscing at. Dignissim sodales ut eu sem integer. Libero justo laoreet sit amet cursus sit amet. Mi tempus imperdiet nulla malesuada pellentesque elit eget gravida cum. Purus faucibus ornare suspendisse sed nisi. Fusce ut placerat orci nulla pellentesque dignissim enim. Bibendum ut tristique et egestas quis ipsum suspendisse ultrices. Nisi est sit amet facilisis. Dolor sed viverra ipsum nunc aliquet. Facilisis magna etiam tempor orci eu lobortis elementum nibh tellus. Ut faucibus pulvinar elementum integer enim neque volutpat.",,,,,,
Notes,Social Note name1,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Eu nisl nunc mi ipsum faucibus. Sed viverra ipsum nunc aliquet bibendum enim. Tortor consequat id porta nibh venenatis cras sed felis. Commodo sed egestas egestas fringilla phasellus faucibus scelerisque eleifend donec. Sodales neque sodales ut etiam sit. Non pulvinar neque laoreet suspendisse interdum consectetur libero id faucibus. Vulputate mi sit amet mauris commodo quis imperdiet. Pellentesque eu tincidunt tortor aliquam. Ut etiam sit amet nisl purus in mollis nunc. Amet est placerat in egestas erat imperdiet sed euismod. Risus at ultrices mi tempus. Pretium vulputate sapien nec sagittis aliquam malesuada bibendum arcu. Mi tempus imperdiet nulla malesuada. Enim neque volutpat ac tincidunt vitae semper. In eu mi bibendum neque egestas. Tincidunt eget nullam non nisi est sit amet facilisis magna.",,,,,,
Notes,Work Note name2,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Turpis massa tincidunt dui ut. Nulla at volutpat diam ut venenatis tellus. Est pellentesque elit ullamcorper dignissim. Nulla facilisi cras fermentum odio eu feugiat pretium nibh ipsum. Enim eu turpis egestas pretium aenean pharetra. Sem et tortor consequat id. Consectetur lorem donec massa sapien faucibus et molestie ac. Tristique sollicitudin nibh sit amet commodo nulla facilisi nullam. Enim diam vulputate ut pharetra sit. Diam maecenas ultricies mi eget mauris pharetra et ultrices. Etiam non quam lacus suspendisse faucibus interdum posuere. Est placerat in egestas erat imperdiet sed euismod nisi porta. Aenean euismod elementum nisi quis eleifend quam adipiscing vitae. Pharetra magna ac placerat vestibulum lectus mauris ultrices eros. Posuere ac ut consequat semper viverra nam libero justo laoreet.",,,,,,
Notes,Reminder Note name3,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At volutpat diam ut venenatis tellus in metus. Nec dui nunc mattis enim ut tellus elementum sagittis vitae. Adipiscing elit ut aliquam purus sit amet luctus venenatis. Pellentesque sit amet porttitor eget dolor. At volutpat diam ut venenatis tellus in metus. Luctus accumsan tortor posuere ac ut consequat semper viverra nam. Id interdum velit laoreet id donec ultrices. Est placerat in egestas erat. Nulla facilisi etiam dignissim diam quis enim lobortis scelerisque. Maecenas volutpat blandit aliquam etiam erat. Accumsan lacus vel facilisis volutpat est velit egestas dui. Adipiscing vitae proin sagittis nisl rhoncus. Arcu non odio euismod lacinia at quis.",,,,,,
Notes,TODO Note name4,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Quisque id diam vel quam elementum pulvinar etiam non. Porta non pulvinar neque laoreet suspendisse interdum consectetur. Quam vulputate dignissim suspendisse in est. Ac auctor augue mauris augue neque gravida. Id eu nisl nunc mi ipsum faucibus vitae aliquet nec. Facilisis magna etiam tempor orci eu lobortis elementum nibh. Non pulvinar neque laoreet suspendisse interdum consectetur libero id. Dolor sit amet consectetur adipiscing elit ut. Quis blandit turpis cursus in hac habitasse platea dictumst quisque. Commodo elit at imperdiet dui accumsan sit amet nulla. Neque gravida in fermentum et sollicitudin ac orci phasellus. Sodales ut etiam sit amet nisl. Ultricies mi quis hendrerit dolor magna eget est. Neque convallis a cras semper auctor. Venenatis urna cursus eget nunc scelerisque viverra mauris in. Arcu dui vivamus arcu felis bibendum ut tristique et. Eleifend mi in nulla posuere sollicitudin aliquam ultrices sagittis orci. Interdum posuere lorem ipsum dolor sit amet consectetur adipiscing. Tellus id interdum velit laoreet.",,,,,,
Notes,Plan Note name5,,,,,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Pellentesque adipiscing commodo elit at imperdiet dui accumsan sit. Magna eget est lorem ipsum dolor sit amet consectetur. Nullam non nisi est sit amet. Molestie nunc non blandit massa enim nec dui nunc mattis. Sapien nec sagittis aliquam malesuada. Laoreet non curabitur gravida arcu ac. Aliquam ultrices sagittis orci a scelerisque purus. Phasellus egestas tellus rutrum tellus pellentesque eu tincidunt tortor aliquam. Nibh praesent tristique magna sit amet. Nunc consequat interdum varius sit amet mattis. Sit amet est placerat in egestas erat imperdiet sed euismod. Interdum posuere lorem ipsum dolor sit. A diam maecenas sed enim ut sem viverra aliquet eget.",,,,,,
Login,Gusto,https://www.gusto.com/,mylogin6,mypassword6,m@gusto.com,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Non curabitur gravida arcu ac. Mus mauris vitae ultricies leo integer malesuada. In massa tempor nec feugiat nisl pretium fusce id velit. Sapien eget mi proin sed libero enim. Dignissim convallis aenean et tortor at risus viverra. Eget felis eget nunc lobortis mattis. Quam id leo in vitae turpis massa sed. Pulvinar sapien et ligula ullamcorper. Blandit turpis cursus in hac habitasse platea. Adipiscing bibendum est ultricies integer quis auctor elit sed. Aliquam nulla facilisi cras fermentum odio eu feugiat pretium. Dictum fusce ut placerat orci nulla pellentesque. Commodo elit at imperdiet dui accumsan sit amet nulla facilisi. Imperdiet massa tincidunt nunc pulvinar sapien et ligula ullamcorper. Facilisi etiam dignissim diam quis enim lobortis scelerisque fermentum. Interdum varius sit amet mattis. Turpis egestas integer eget aliquet nibh. Dignissim cras tincidunt lobortis feugiat vivamus.",,,,,,
Login,outlook,https://www.outlook.com/,mylogin8,mypassword8,me@outlook.com,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Netus et malesuada fames ac turpis egestas sed tempus urna. Cursus in hac habitasse platea dictumst quisque sagittis purus sit. Non sodales neque sodales ut etiam sit amet nisl purus. Adipiscing elit pellentesque habitant morbi tristique senectus. Habitant morbi tristique senectus et netus et malesuada fames. Scelerisque viverra mauris in aliquam. Nibh cras pulvinar mattis nunc sed blandit libero volutpat sed. Ut morbi tincidunt augue interdum velit. Enim nulla aliquet porttitor lacus. Posuere morbi leo urna molestie at elementum. Lobortis scelerisque fermentum dui faucibus in ornare quam viverra orci. Sed cras ornare arcu dui vivamus arcu. Congue mauris rhoncus aenean vel. Varius sit amet mattis vulputate enim nulla. Vulputate dignissim suspendisse in est ante in. Odio facilisis mauris sit amet. Fringilla est ullamcorper eget nulla. Dolor sit amet consectetur adipiscing. Pellentesque nec nam aliquam sem et tortor.",,,,,,
Login,Streamer,https://www.twitch.tv/,mylogin6,mypassword6,sam@wealth.io,,"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Vitae justo eget magna fermentum. Purus sit amet luctus venenatis lectus magna fringilla. Lorem sed risus ultricies tristique nulla. Maecenas accumsan lacus vel facilisis volutpat est velit. Lorem ipsum dolor sit amet consectetur adipiscing elit ut. Sed blandit libero volutpat sed cras ornare arcu dui. Semper auctor neque vitae tempus quam pellentesque nec nam. Dui sapien eget mi proin sed libero enim sed faucibus. Nullam ac tortor vitae purus faucibus ornare. Viverra orci sagittis eu volutpat odio facilisis mauris.",,,,,,
Login,Manning,https://www.manning.com/,loginx,passwordx,manning@manning.io,,Lorem ipsum dolor sit amet,,,,,,
Login,Experian,https://www.experian.com/,exloginx,passwordx,me@experian.io,,Lorem ipsum dolor sit amet,,,,,,
Login,Best buy,https://www.bestbuy.com/,bbloginx,passwordx,me@bestbuy.io,,Lorem ipsum dolor sit amet,,,,,,"""

class ImportExportTest(unittest.TestCase):
    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_get_vaults(self):
        global VAULT_ID1
        global VAULT_ID2
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        VAULT_ID1 = json.loads(resp.text)[0]['vault_id']
        VAULT_ID2 = json.loads(resp.text)[1]['vault_id']

    def test_03_import_accounts(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID1 + '/import', data = DATA1, headers = headers, verify = False)
        # 409 indicates duplicate accounts
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_04_import_accounts(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID2 + '/import', data = DATA2, headers = headers, verify = False)
        # 409 indicates duplicate accounts
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_05_export_accounts(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        info = {}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID1 + '/export', json = info, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.text.count('\n') >= 15)
        self.assertIn('Amazon', resp.text)
        self.assertIn('Twitter', resp.text)

    def test_06_export_accounts_encrypted(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        info = {'password': 'mypass', 'encoding': 'Base64'}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID1 + '/export', json = info, headers = headers, verify = False)
        encrypted = resp.text
        resp = requests.post(SERVER + '/api/v1/encryption/symmetric_decrypt/' + info['password'], data = encrypted.encode('utf-8'), headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        count = resp.text.count('\n')
        self.assertTrue(count >= 15)
        self.assertIn('Amazon', resp.text)
        self.assertIn('Twitter', resp.text)

if __name__ == '__main__':
    unittest.main()
