// date format: d MMM yyyy, H:mm, time should be specifed based on UTC time

export type EventData = {
  id: string;
  title: string;
  isActive?: boolean;
  validTill: string;
  bodyText: string | string[];
  buttons: {
    text: string;
    link: string;
    newTab: boolean;
  }[];
};

export const homeEventsData: EventData[] = [];

export const appEventsData: EventData[] = [
  // {
  //   id: "ulp-manager-updates",
  //   title: "ULP Manager Updates",
  //   isActive: true,
  //   validTill: "18 Dec 2022, 12:00",
  //   bodyText:
  //     "The ULP Manager address has been updated based on the linked post, existing users will need to approve the new ULP Manager to buy ULP tokens.",
  //   buttons: [
  //     {
  //       text: "Read More",
  //       link: "https://medium.com/@utx.io/utx-deployment-updates-nov-2022-16572314874d",
  //       newTab: true,
  //     },
  //   ],
  // },
];
