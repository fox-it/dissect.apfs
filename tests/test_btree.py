from __future__ import annotations

from unittest.mock import Mock

from dissect.apfs.objects.btree import BTree


def test_node_search_empty_node() -> None:
    """Test that searching a node without keys finds nothing instead of raising an error."""
    btree = BTree.__new__(BTree)
    node = Mock(nkeys=0)

    assert btree._node_search(node, b"key") == -1
    assert btree._node_search(node, b"key", exact=True) == -1
