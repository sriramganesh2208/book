import React, { useState, useEffect } from "react";
import Navbar from "../../components/navbar/Navbar";
import { useLocation } from "react-router-dom";
import { format } from "date-fns";
import { DateRange } from "react-date-range";
import SearchItem from "../../components/searchItem/SearchItem";
import useFetch from "../../hooks/useFetch";
import { Checkbox, FormControlLabel, Button, TextField } from '@mui/material';
import "./list.css";

const List = () => {
  const location = useLocation();
  const [destination, setDestination] = useState(location.state.destination || '');
  const [dates, setDates] = useState(location.state.dates || [{ startDate: new Date(), endDate: new Date() }]);
  const [openDate, setOpenDate] = useState(false);
  const [options, setOptions] = useState(location.state.options);
  const [min, setMin] = useState(undefined);
  const [max, setMax] = useState(undefined);
  const [sortBy, setSortBy] = useState('');
  const [accommodationTypes, setAccommodationTypes] = useState({
    hotel: false,
    villa: false,
    apartment: false,
    resort: false,
    cabin: false
  });
  const [searchQuery, setSearchQuery] = useState('');

  const handleSortChange = (event) => {
    setSortBy(event.target.value);
  };

  const { data, loading, error, reFetch } = useFetch(
    `/hotels?city=${destination}&min=${min || 0}&max=${max || 9999}&sort=${sortBy}`
  );

  const handlePriceChange = (event) => {
    const { name, checked } = event.target;
    switch (name) {
      case "upto2000":
        setMin(undefined);
        setMax(2000);
        break;
      case "from2001to4000":
        setMin(2001);
        setMax(4000);
        break;
      case "from4001to6000":
        setMin(4001);
        setMax(6000);
        break;
      case "over6001":
        setMin(6001);
        setMax(undefined);
        break;
      default:
        break;
    }
  };

  const handleResetPriceRange = () => {
    setMin(undefined);
    setMax(undefined);
  };

  const handleClick = () => {
    reFetch();
  };

  const handleAccommodationTypeChange = (event) => {
    const { name, checked } = event.target;
    setAccommodationTypes({
      ...accommodationTypes,
      [name]: checked
    });
  };

  const [sortedData, setSortedData] = useState([]);

  useEffect(() => {
    if (data.length > 0 && Object.values(accommodationTypes).some(Boolean)) {
      const filteredData = data.filter(item => accommodationTypes[item.type]);
      const sorted = filteredData.sort((a, b) => {
        const types = ["hotel", "resort", "apartment", "villa", "cabin"];
        return types.indexOf(a.type) - types.indexOf(b.type);
      });
      setSortedData(sorted);
    } else {
      setSortedData(data);
    }
  }, [data, accommodationTypes]);

  useEffect(() => {
    const filteredData = data.filter(item => item.name.toLowerCase().includes(searchQuery.toLowerCase()));
    setSortedData(filteredData);
  }, [searchQuery, data]);

  // Function to handle destination change
  const handleDestinationChange = (event) => {
    setDestination(event.target.value);
  };

  // Function to handle date change
  const handleDateChange = (ranges) => {
    setDates([ranges.selection]);
  };

  // Sorting options
  const sortingOptions = [
    { label: "Price Low To High", value: "lowToHigh" },
    { label: "Price High To Low", value: "highToLow" }
  ];

  const handleSortLowToHigh = () => {
    setSortBy('lowToHigh');
  };

  const handleSortHighToLow = () => {
    setSortBy('highToLow');
  };

  return (
    <div>
      <Navbar />

      <div className="top">
        <div className="prices">
          <h3>Sort by:</h3>
          <Button variant="outlined" onClick={handleSortLowToHigh}>Low To High</Button>
          <Button variant="outlined" onClick={handleSortHighToLow}>High To Low</Button>
        </div>

        <div className="searchBox">
          <TextField
            id="filled-basic"
            label="Search Hotel Name"
            variant="filled"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="listContainer">
        <div className="listWrapper">
          <div className="listSearch">
            <div className="list">
              <h3 className="lsTitle">Search</h3>

              <div className="lsItem">
                <label>Destination</label>
                <TextField
                  id="outlined-basic"
                  variant="outlined"
                  value={destination}
                  onChange={handleDestinationChange}
                  type="text"
                />
              </div>
              <div className="lsItem">
                <label>Check-in Date</label>
                <span onClick={() => setOpenDate(!openDate)}>{`${format(
                  dates[0].startDate,
                  "MM/dd/yyyy"
                )} to ${format(dates[0].endDate, "MM/dd/yyyy")}`}</span>
                {openDate && (
                  <DateRange
                    onChange={handleDateChange}
                    minDate={new Date()}
                    ranges={dates}
                  />
                )}
              </div>
              <div className="lsItem">
                <label>Options</label>
                <div className="lsOptions">
                  <div className="lsOptionItem">
                    <span className="lsOptionText">
                      Min price <small>per night</small>
                    </span>
                    <input
                      type="number"
                      onChange={(e) => setMin(e.target.value)}
                      className="lsOptionInput"
                    />
                  </div>
                  <div className="lsOptionItem">
                    <span className="lsOptionText">
                      Max price <small>per night</small>
                    </span>
                    <input
                      type="number"
                      onChange={(e) => setMax(e.target.value)}
                      className="lsOptionInput"
                    />
                  </div>
                  <div className="lsOptionItem">
                    <span className="lsOptionText">Adult</span>
                    <input
                      type="number"
                      min={1}
                      className="lsOptionInput"
                      placeholder={options.adult}
                    />
                  </div>
                  <div className="lsOptionItem">
                    <span className="lsOptionText">Children</span>
                    <input
                      type="number"
                      min={0}
                      className="lsOptionInput"
                      placeholder={options.children}
                    />
                  </div>
                  <div className="lsOptionItem">
                    <span className="lsOptionText">Room</span>
                    <input
                      type="number"
                      min={1}
                      className="lsOptionInput"
                      placeholder={options.room}
                    />
                  </div>
                </div>
              </div>
              <Button variant="contained" onClick={handleClick}>Search</Button>
            </div>

            <div className="checkbox">
              <h3>Price Range</h3>
              <div className="checkboxContainer">
                <FormControlLabel
                  control={<Checkbox checked={min === undefined && max === 2000} onChange={handlePriceChange} name="upto2000" />}
                  label="Up to 2000"
                />
                <FormControlLabel
                  control={<Checkbox checked={min === 2001 && max === 4000} onChange={handlePriceChange} name="from2001to4000" />}
                  label="2001 to 4000"
                />
                <FormControlLabel
                  control={<Checkbox checked={min === 4001 && max === 6000} onChange={handlePriceChange} name="from4001to6000" />}
                  label="4001 to 6000"
                />
                <FormControlLabel
                  control={<Checkbox checked={min === 6001 && max === undefined} onChange={handlePriceChange} name="over6001" />}
                  label="6001+"
                />
              </div>
              <Button variant="contained" onClick={handleResetPriceRange}>Reset Price Range</Button>
            </div>

            <div className="checkbox">
              <h3>Accommodation Types</h3>
              <div className="checkboxContainer">
                <FormControlLabel
                  control={<Checkbox checked={accommodationTypes.hotel} onChange={handleAccommodationTypeChange} name="hotel" />}
                  label="Hotel"
                />
                <FormControlLabel
                  control={<Checkbox checked={accommodationTypes.villa} onChange={handleAccommodationTypeChange} name="villa" />}
                  label="Villa"
                />
                <FormControlLabel
                  control={<Checkbox checked={accommodationTypes.apartment} onChange={handleAccommodationTypeChange} name="apartment" />}
                  label="Apartment"
                />
                <FormControlLabel
                  control={<Checkbox checked={accommodationTypes.resort} onChange={handleAccommodationTypeChange} name="resort" />}
                  label="Resort"
                />
                <FormControlLabel
                  control={<Checkbox checked={accommodationTypes.cabin} onChange={handleAccommodationTypeChange} name="cabin" />}
                  label="Cabin"
                />
              </div>
            </div>
          </div>
          <div className="listResult">
            {loading ? (
              "Loading..."
            ) : (
              <>
                {sortedData.map((item) => (
                  <SearchItem item={item} key={item._id} />
                ))}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default List;

