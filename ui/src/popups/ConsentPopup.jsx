import { useState } from "react";
import { Modal } from "antd";
import "../styles/popup.scss";
import ConsentForm from "../forms/ConsentForm";
import URL_PARAMS from "../constants/urlParams";

export default function ConsentPopup() {
  const [visible, setVisible] = useState(true);

  const urlParams = new URLSearchParams(window.location.search);
  const redirectURI = urlParams.get(URL_PARAMS.REDIRECT_URI);

  const onCancel = () => {
    console.log(redirectURI);
    setVisible(false);
  };

  const afterClose = () => {
    if (redirectURI) {
      window.location.replace(redirectURI);
    }
  };

  return (
    <Modal
      open={visible}
      onCancel={onCancel}
      width={450}
      maskClosable={true}
      className="custom-popup"
      afterClose={afterClose}
      footer={null}
      centered
    >
      <ConsentForm />
    </Modal>
  );
}
