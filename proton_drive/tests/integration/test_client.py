import hashlib

import pytest

from proton_drive.client import ProtonDriveClient
from proton_drive.models.drive import DriveNode, NodeType

EXPECTED_TREE = {
    "/test_fixtures": NodeType.FOLDER,
    "/test_fixtures/subfolder": NodeType.FOLDER,
    "/test_fixtures/subfolder/nested.txt": NodeType.FILE,
    "/test_fixtures/data.json": NodeType.FILE,
    "/test_fixtures/large_file.dat": NodeType.FILE,
    "/test_fixtures/empty.txt": NodeType.FILE,
    "/test_fixtures/binary.bin": NodeType.FILE,
    "/test_fixtures/simple.txt": NodeType.FILE,
    "/test_fixtures/unicode.txt": NodeType.FILE,
    "/empty.txt": NodeType.FILE,
}

EXPECTED_FILE_HASHES = {
    "/test_fixtures/subfolder/nested.txt": "1f4faae9f381a7e449bce0053e70ede7dfcf4d59cc9e621e2e94d1050389fd9f",
    "/test_fixtures/data.json": "d67b15e5068f3d80ff30f074553a39601902df61f9045bb98b0ce81f725cd83a",
    "/test_fixtures/large_file.dat": "3024aacad846589f341544494753d4f0a2d925125f789bc8e21a0865a8600375",
    "/test_fixtures/empty.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "/test_fixtures/binary.bin": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
    "/test_fixtures/simple.txt": "0f9af4b4d0ee217efc1a195b21b6d517644755c30cee613072cbb210acd37b60",
    "/test_fixtures/unicode.txt": "f1e58b18d4d8486b96ea53a4ffc2ea4c3086c2cd3ce8d7569a44114ef5156734",
    "/empty.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def collect_paths(node: DriveNode, current: str = "") -> dict[str, NodeType]:
    result = {}
    for child in node.children:
        path = f"{current}/{child.name}"
        result[path] = child.node_type
        if child.node_type == NodeType.FOLDER:
            result.update(collect_paths(child, path))
    return result


@pytest.fixture(scope="module")
async def authenticated_client(proton_credentials: tuple[str, str]) -> ProtonDriveClient:
    username, password = proton_credentials
    async with ProtonDriveClient() as client:
        await client.authenticate(username, password)
        yield client


@pytest.mark.integration
async def test_authenticate_succeeds(authenticated_client: ProtonDriveClient) -> None:
    assert authenticated_client.is_authenticated
    assert authenticated_client.has_drive_access


@pytest.mark.integration
async def test_build_tree_matches_expected(authenticated_client: ProtonDriveClient) -> None:
    root = await authenticated_client.build_tree()
    assert isinstance(root, DriveNode)
    assert root.node_type == NodeType.FOLDER

    actual = collect_paths(root)
    assert actual == EXPECTED_TREE


@pytest.mark.integration
async def test_get_node_returns_none_for_missing_path(
    authenticated_client: ProtonDriveClient,
) -> None:
    node = await authenticated_client.get_node("/this_path_does_not_exist_xyz")
    assert node is None


@pytest.mark.integration
@pytest.mark.parametrize("path,expected_hash", list(EXPECTED_FILE_HASHES.items()))
async def test_download_file_hash_matches(
    authenticated_client: ProtonDriveClient,
    path: str,
    expected_hash: str,
) -> None:
    hasher = hashlib.sha256()
    async for chunk in authenticated_client.download_file(path):
        hasher.update(chunk)
    assert hasher.hexdigest() == expected_hash
