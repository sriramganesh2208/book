import useFetch from "../../hooks/useFetch";
import "./featured.css";


const Featured = () => {
  const { data, loading, error } = useFetch(
    "/hotels/countByCity?cities=berlin,madrid,london,australia"
  );

  return (
    <div className="featured">
      {loading ? (
        "Loading please wait"
      ) : (
        <>
       

            {/* Slides */}
            <div className="featuredItem">
             
                <img
                  src="https://images.unsplash.com/photo-1562133567-b6a0a9c7e6eb?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxzZWFyY2h8NzZ8fGhvdGVsfGVufDB8fDB8fHww"
                  alt=""
                  className="featuredImg"
                />
                <div className="featuredTitles">
                  <h1>Berlin</h1>
                  <h2>{data[0]} properties</h2>
                </div>
         
            </div>

            <div className="featuredItem">
        
                <img
                  src="https://images.unsplash.com/photo-1578774204375-826dc5d996ed?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxzZWFyY2h8OTV8fGhvdGVsfGVufDB8fDB8fHww"
                  alt=""
                  className="featuredImg"
                />
                <div className="featuredTitles">
                  <h1>Madrid</h1>
                  <h2>{data[1]} properties</h2>
                </div>
         
            </div>

            <div className="featuredItem">
            
                <img
                  src="https://images.unsplash.com/photo-1619634727222-3318c5e9ebd7?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MTg4fHxob3RlbHxlbnwwfHwwfHx8MA%3D%3D"
                  alt=""
                  className="featuredImg"
                />
                <div className="featuredTitles">
                  <h1>London</h1>
                  <h2>{data[2]} properties</h2>
                </div>
          
            </div>

            <div className="featuredItem">
            
                <img
                  src="https://images.pexels.com/photos/1761279/pexels-photo-1761279.jpeg?auto=compress&cs=tinysrgb&w=600"
                  alt=""
                  className="featuredImg"
                />
                <div className="featuredTitles">
                  <h1>Australia</h1>
                  <h2>{data[3]} properties</h2>
                </div>
           
            </div>
      
        </>
      )}
    </div>
  );
};

export default Featured;
