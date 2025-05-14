import { useState } from "react";
import { Modal } from "antd";
import { useApplicationContext } from "../context/ApplicationContext";
import ConsentForm from "../forms/ConsentForm";
import "../styles/popup.scss";

export default function ConsentPopup() {
  const [visible, setVisible] = useState(true);
  const { redirectURI } = useApplicationContext();

  const onCancel = () => {
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
