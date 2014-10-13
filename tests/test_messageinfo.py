def test_setId(self):
    # Check info db load_msg is called.
    self.msg.id = None
    saved = self.msg.message_info_db.load_msg
    self.done = False
    try:
        self.msg.message_info_db.load_msg = self._fake_setState
        self.msg.set_id(id)
        self.assertEqual(self.done, True)
    finally:
        self.msg.message_info_db.load_msg = saved

def _fake_setState(self, state):
    self.done = True

def test_modified(self):
    saved = self.msg.message_info_db.store_msg
    try:
        self.msg.message_info_db.store_msg = self._fake_setState
        self.done = False
        self.msg.modified()
        self.assertEqual(self.done, False)
        self.msg.id = "Test"
        self.msg.modified()
        self.assertEqual(self.done, True)
    finally:
        self.msg.message_info_db.store_msg = saved

