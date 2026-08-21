from fastapi.testclient import TestClient

from examples.reference_sut.app import app


client = TestClient(app)


def test_reference_sut_exposes_every_controlled_contract_mode() -> None:
    modes = {
        "pass",
        "app-defect",
        "outdated-locator",
        "api-failure",
        "timing",
        "invalid-data",
        "prompt-injection",
    }

    for mode in modes:
        response = client.get("/", params={"mode": mode})
        assert response.status_code == 200
        assert "Reference Checkout" in response.text


def test_outdated_locator_preserves_accessible_behavior_but_changes_fragile_test_id() -> None:
    response = client.get("/", params={"mode": "outdated-locator"})

    assert response.status_code == 200
    assert 'role="button" aria-label="Place order"' in response.text
    assert 'data-testid="checkout-submit"' in response.text
    assert 'data-testid="place-order"' not in response.text


def test_invalid_data_mode_produces_real_request_validation_failure() -> None:
    page = client.get("/", params={"mode": "invalid-data"})
    response = client.post(
        "/api/orders",
        params={"mode": "invalid-data"},
        json={"sku": "widget-1", "quantity": 0},
    )

    assert page.status_code == 200
    assert 'id="qty" type="number" value="0"' in page.text
    assert response.status_code == 422


def test_pass_mode_accepts_valid_order() -> None:
    response = client.post(
        "/api/orders",
        params={"mode": "pass"},
        json={"sku": "widget-1", "quantity": 1},
    )

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "order_id": "order-demo-001",
        "sku": "widget-1",
        "quantity": 1,
    }
