import { Card } from "antd";
import FlexContainer from "../components/FlexContainer";
import ConsentForm from "../forms/ConsentForm";
import ConsentPopup from "../popups/ConsentPopup";
import "../styles/ConsentPage.scss";

export default function ConsentPage({ display }) {
  return display === "popup" ? (
    <ConsentPopup />
  ) : (
    <FlexContainer className="consent-form-container">
      <Card className="consent-card" variant="borderless">
        {<ConsentForm />}
      </Card>
    </FlexContainer>
  );
}
