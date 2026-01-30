from proton_drive.models.drive import DriveNode, NodeType, _format_size


def test_format_size_returns_human_readable_values() -> None:
    assert _format_size(0) == "0 B"
    assert _format_size(512) == "512 B"
    assert _format_size(1023) == "1023 B"
    assert _format_size(1024) == "1.0 KB"
    assert _format_size(1536) == "1.5 KB"
    assert _format_size(1024 * 1024) == "1.0 MB"
    assert _format_size(1024**3) == "1.0 GB"
    assert _format_size(1024**4) == "1.0 TB"


def test_to_dict_returns_folder_representation() -> None:
    node = DriveNode(
        link_id="folder-1",
        parent_link_id=None,
        name="Documents",
        node_type=NodeType.FOLDER,
    )
    assert node.to_dict() == {"name": "Documents", "type": "folder", "link_id": "folder-1"}


def test_to_dict_returns_file_representation_with_size_and_mime() -> None:
    node = DriveNode(
        link_id="file-1",
        parent_link_id="folder-1",
        name="report.pdf",
        node_type=NodeType.FILE,
        size=1024,
        mime_type="application/pdf",
    )
    assert node.to_dict() == {
        "name": "report.pdf",
        "type": "file",
        "link_id": "file-1",
        "size": 1024,
        "mime_type": "application/pdf",
    }


def test_to_dict_includes_children_recursively() -> None:
    child = DriveNode(
        link_id="file-1",
        parent_link_id="folder-1",
        name="file.txt",
        node_type=NodeType.FILE,
        size=100,
        mime_type="text/plain",
    )
    parent = DriveNode(
        link_id="folder-1",
        parent_link_id=None,
        name="Root",
        node_type=NodeType.FOLDER,
        children=(child,),
    )

    assert parent.to_dict()["children"][0]["name"] == "file.txt"


def test_get_child_returns_matching_child() -> None:
    child = DriveNode(link_id="2", parent_link_id="1", name="child", node_type=NodeType.FILE)
    parent = DriveNode(
        link_id="1",
        parent_link_id=None,
        name="parent",
        node_type=NodeType.FOLDER,
        children=(child,),
    )

    assert parent.get_child("child") is child
    assert parent.get_child("nonexistent") is None


def test_find_returns_node_by_path() -> None:
    file = DriveNode(link_id="3", parent_link_id="2", name="file.txt", node_type=NodeType.FILE)
    subfolder = DriveNode(
        link_id="2",
        parent_link_id="1",
        name="subfolder",
        node_type=NodeType.FOLDER,
        children=(file,),
    )
    root = DriveNode(
        link_id="1",
        parent_link_id=None,
        name="root",
        node_type=NodeType.FOLDER,
        children=(subfolder,),
    )

    assert root.find("/") is root
    assert root.find("/subfolder/file.txt") is file
    assert root.find("/nonexistent") is None


def test_walk_traverses_tree_depth_first() -> None:
    deep_file = DriveNode(link_id="4", parent_link_id="2", name="deep", node_type=NodeType.FILE)
    subfolder = DriveNode(
        link_id="2",
        parent_link_id="1",
        name="sub",
        node_type=NodeType.FOLDER,
        children=(deep_file,),
    )
    file_at_root = DriveNode(
        link_id="3", parent_link_id="1", name="root_file", node_type=NodeType.FILE
    )
    root = DriveNode(
        link_id="1",
        parent_link_id=None,
        name="root",
        node_type=NodeType.FOLDER,
        children=(subfolder, file_at_root),
    )

    result = list(root.walk())

    assert len(result) == 4
    assert [depth for _, depth in result] == [0, 1, 2, 1]
