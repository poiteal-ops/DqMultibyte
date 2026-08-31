from mbscan.oracle.metadata import database_character_set


class _OneValueCursor:
    def __init__(self, value):
        self._value = value
        self.executed = []

    def execute(self, sql, parameters=None):
        self.executed.append((sql, parameters))

    def fetchone(self):
        return (self._value,)


def test_database_character_set_reads_nls_database_parameters():
    cursor = _OneValueCursor("AL32UTF8")

    result = database_character_set(cursor)

    assert result == "AL32UTF8"
    sql, _ = cursor.executed[0]
    assert "nls_database_parameters" in sql.lower()
    assert "NLS_CHARACTERSET" in sql
